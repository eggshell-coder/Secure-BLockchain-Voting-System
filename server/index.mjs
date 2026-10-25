import { createServer } from "node:http";
import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual
} from "node:crypto";
import { ristretto255 } from "@noble/curves/ed25519.js";
import { acceptVerifiedBallot } from "./ballot-verifier.mjs";
import { createSemaphoreGroup, verifySemaphoreProofForBallot } from "./semaphore-verifier.mjs";
import { relayVerifiedBallot } from "./chain-relayer.mjs";
import { canonicalJson } from "../lib/crypto/proofs.ts";
import { shuffleCommitments } from "./semaphore-enrollment.mjs";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const publicDir = path.join(root, "public");

function loadDotEnv() {
  const envPath = path.join(root, ".env");
  if (!existsSync(envPath)) return;
  for (const line of readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const match = line.trim().match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match || match[1].startsWith("#") || process.env[match[1]] !== undefined) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[match[1]] = value;
  }
}

loadDotEnv();
const dataDir = path.resolve(root, process.env.DATA_DIR ?? "./data");
mkdirSync(dataDir, { recursive: true });

const isProduction = process.env.NODE_ENV === "production";
const supabaseUrl = (process.env.SUPABASE_URL ?? "").replace(/\/+$/, "");
const supabaseServiceKey = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const supabasePublishableKey = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || "";
const voterEmailDomains = (process.env.VOTER_EMAIL_DOMAINS ?? "")
  .split(",")
  .map((domain) => domain.trim().toLowerCase().replace(/^@/, ""))
  .filter(Boolean);
if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error("Set SUPABASE_URL and a server-only SUPABASE_SECRET_KEY (or legacy SUPABASE_SERVICE_ROLE_KEY) in .env.");
}
const supabaseOrigin = new URL(supabaseUrl).origin;
if (isProduction) {
  const required = ["ADMIN_EMAIL", "ADMIN_PASSWORD", "JWT_SECRET", "SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "VOTER_EMAIL_DOMAINS"];
  const missing = required.filter((key) => !process.env[key]);
  const jwtSecretValue = process.env.JWT_SECRET ?? "";
  if (missing.length || jwtSecretValue.length < 32 || /replace-with|change-this/i.test(jwtSecretValue) || (process.env.ADMIN_PASSWORD ?? "").length < 14 || /change-|replace-with/i.test(process.env.ADMIN_PASSWORD ?? "")) {
    throw new Error("Production requires ADMIN_EMAIL, a non-placeholder ADMIN_PASSWORD of at least 14 characters, a JWT_SECRET of at least 32 characters, a Supabase publishable key, and an explicit voter email-domain allowlist.");
  }
}

const localSecretPath = path.join(dataDir, "local-secrets.json");
const secretFileExisted = existsSync(localSecretPath);
let localSecrets = {};
if (existsSync(localSecretPath)) {
  try {
    localSecrets = JSON.parse(readFileSync(localSecretPath, "utf8"));
  } catch {
    throw new Error("Local secret file is unreadable. Restore data/local-secrets.json or remove it to generate new local secrets.");
  }
}
let localSecretChanged = false;
for (const key of ["JWT_SECRET"]) {
  if (!process.env[key] && (typeof localSecrets[key] !== "string" || !/^[0-9a-f]{64}$/i.test(localSecrets[key]))) {
    localSecrets[key] = randomBytes(32).toString("hex");
    localSecretChanged = true;
  }
}
if (localSecretChanged) writeFileSync(localSecretPath, `${JSON.stringify(localSecrets, null, 2)}\n`, secretFileExisted ? {} : { flag: "wx", mode: 0o600 });
const jwtSecret = process.env.JWT_SECRET || localSecrets.JWT_SECRET;

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function passwordHash(password, salt) {
  return scryptSync(password, salt, 64).toString("hex");
}

function tokenFor(payload, lifetimeSeconds = 60 * 60 * 8) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + lifetimeSeconds })).toString("base64url");
  const unsigned = `${header}.${body}`;
  const signature = createHmac("sha256", jwtSecret).update(unsigned).digest("base64url");
  return `${unsigned}.${signature}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = createHmac("sha256", jwtSecret).update(unsigned).digest("base64url");
  if (!safeEqual(parts[2], expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

function cookieValue(req, name) {
  const raw = req.headers.cookie ?? "";
  for (const part of raw.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
  return null;
}

function setSessionCookie(res, token) {
  const secure = isProduction ? "; Secure" : "";
  res.setHeader("Set-Cookie", `session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
}

function clearSessionCookie(res) {
  const secure = isProduction ? "; Secure" : "";
  res.setHeader("Set-Cookie", `session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
}

function sessionFor(req) {
  return verifyToken(cookieValue(req, "session"));
}

function requireAdmin(req) {
  const session = sessionFor(req);
  if (!session || session.role !== "admin") {
    const error = new Error("Administrator sign-in required.");
    error.status = 401;
    throw error;
  }
  return session;
}

function canonicalManifest(election, candidates) {
  const manifest = {
    electionId: String(election.id ?? election.election_id),
    title: election.title,
    description: election.description,
    startsAt: new Date(election.startsAt ?? election.starts_at).toISOString(),
    endsAt: new Date(election.endsAt ?? election.ends_at).toISOString(),
    ...(election.electionPublicKey ? { electionPublicKey: election.electionPublicKey } : {}),
    candidates: candidates.map((item, index) => ({
      position: index + 1,
      name: item.name ?? item.display_name,
      manifesto: item.manifesto
    }))
  };
  return JSON.stringify(manifest);
}

function isValidElectionPublicKey(publicKey) {
  if (typeof publicKey !== "string" || !/^[a-f0-9]{64}$/.test(publicKey)) return false;
  try {
    const bytes = Buffer.from(publicKey, "hex");
    const point = ristretto255.Point.fromBytes(bytes);
    point.assertValidity();
    return !point.is0() && Buffer.from(point.toBytes()).toString("hex") === publicKey;
  } catch {
    return false;
  }
}

async function supabaseRequest(resource, { method = "GET", body } = {}) {
  const response = await fetch(`${supabaseUrl}/rest/v1/${resource}`, {
    method,
    headers: {
      apikey: supabaseServiceKey,
      Authorization: `Bearer ${supabaseServiceKey}`,
      Accept: "application/json",
      ...(body === undefined ? {} : { "Content-Type": "application/json" })
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(12_000)
  });
  const raw = await response.text();
  let result = null;
  if (raw) {
    try { result = JSON.parse(raw); } catch { result = raw; }
  }
  if (!response.ok) {
    const error = new Error(`Supabase request failed with HTTP ${response.status}.`);
    error.status = response.status;
    error.details = result;
    throw error;
  }
  return result;
}

async function readSemaphoreCommitments(electionId, pending = false) {
  const table = pending ? "semaphore_pending_commitments" : "semaphore_group_members";
  const order = pending ? "identity_commitment.asc" : "member_index.asc";
  const commitments = [];
  for (let offset = 0; ; offset += 500) {
    const rows = await supabaseRequest(
      `${table}?select=identity_commitment&election_id=eq.${encodeURIComponent(electionId)}&order=${order}&limit=500&offset=${offset}`
    );
    commitments.push(...(rows ?? []).map((row) => String(row.identity_commitment)));
    if (!rows || rows.length < 500) return commitments;
  }
}

function rpc(name, args) {
  return supabaseRequest(`rpc/${name}`, { method: "POST", body: args });
}

function hashFromBytea(value) {
  return typeof value === "string" && value.startsWith("\\x") ? value.slice(2) : value;
}

function mapElectionRow(row, candidates) {
  const candidateList = candidates.map((candidate) => ({
    id: candidate.candidate_id,
    name: candidate.display_name,
    manifesto: candidate.manifesto
  }));
  const election = {
    id: row.election_id,
    title: row.title,
    description: row.description,
    startsAt: new Date(row.starts_at).toISOString(),
    endsAt: new Date(row.ends_at).toISOString(),
    status: row.status === "scheduled"
      ? new Date(row.ends_at).getTime() <= Date.now() ? "closed"
        : new Date(row.starts_at).getTime() <= Date.now() ? "active" : "scheduled"
      : row.status,
    electionPublicKey: row.election_public_key ?? null,
    keyCeremonyStatus: row.key_ceremony_status ?? "not_started",
    semaphoreGroupRoot: row.semaphore_group_root === null || row.semaphore_group_root === undefined
      ? null : String(row.semaphore_group_root),
    semaphoreGroupFrozenAt: row.semaphore_group_frozen_at ?? null,
    candidates: candidateList
  };
  election.manifestHash = hashFromBytea(row.manifest_hash) ?? hash(canonicalManifest(election, candidateList));
  return election;
}

async function getElection(id) {
  const rows = await supabaseRequest(`elections?select=election_id,title,description,starts_at,ends_at,status,manifest_hash,election_public_key,key_ceremony_status,semaphore_group_root,semaphore_group_frozen_at&election_id=eq.${encodeURIComponent(id)}&limit=1`);
  const row = rows?.[0];
  if (!row) return null;
  const candidates = await supabaseRequest(`candidates?select=candidate_id,display_name,manifesto,list_order&election_id=eq.${encodeURIComponent(id)}&order=list_order.asc`);
  return mapElectionRow(row, candidates ?? []);
}

async function listElections(includeDrafts = false) {
  const statusFilter = includeDrafts ? "" : "&status=neq.draft";
  const rows = await supabaseRequest(`elections?select=election_id,title,description,starts_at,ends_at,status,manifest_hash,election_public_key,key_ceremony_status,semaphore_group_root,semaphore_group_frozen_at&order=created_at.desc${statusFilter}`);
  const result = await Promise.all((rows ?? []).map((row) => getElection(row.election_id)));
  return result.filter(Boolean);
}

const adminEmail = (process.env.ADMIN_EMAIL || "admin@demo.local").trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || "change-me-now";
const adminSalt = hash(`secure-voting-admin:${adminEmail}:${jwtSecret}`).slice(0, 32);
const configuredAdminPasswordHash = passwordHash(adminPassword, adminSalt);

async function verifySupabaseConnection() {
  await supabaseRequest("elections?select=election_id&limit=1");
}

function isAllowedVoterEmail(email) {
  const domain = String(email ?? "").trim().toLowerCase().split("@").at(-1);
  return voterEmailDomains.includes(domain);
}

async function requireVerifiedVoterAuth(req) {
  if (!supabasePublishableKey || voterEmailDomains.length === 0) {
    const error = new Error("Supabase Auth and the student email-domain allowlist must be configured first.");
    error.status = 503;
    throw error;
  }
  const match = String(req.headers.authorization ?? "").match(/^Bearer\s+(\S+)$/i);
  if (!match || match[1].length > 8192) {
    const error = new Error("Sign in with your verified university account first.");
    error.status = 401;
    throw error;
  }

  let response;
  try {
    response = await fetch(`${supabaseUrl}/auth/v1/user`, {
      headers: {
        apikey: supabasePublishableKey,
        Authorization: `Bearer ${match[1]}`,
        Accept: "application/json"
      },
      signal: AbortSignal.timeout(8_000)
    });
  } catch {
    const error = new Error("Supabase Auth could not be reached. Try again shortly.");
    error.status = 503;
    throw error;
  }
  if (!response.ok) {
    const error = new Error("Your sign-in session is invalid or expired. Sign in again.");
    error.status = 401;
    throw error;
  }

  const user = await response.json().catch(() => null);
  const email = String(user?.email ?? "").trim().toLowerCase();
  if (!user?.id || !/^[0-9a-f-]{36}$/i.test(user.id) || !email || !user.email_confirmed_at) {
    const error = new Error("Sign in with your confirmed university email account to register.");
    error.status = 403;
    throw error;
  }
  if (!isAllowedVoterEmail(email)) {
    const error = new Error("Use an approved student email domain for this election.");
    error.status = 403;
    throw error;
  }
  return { id: user.id, email };
}

const cryptoReadiness = Object.freeze({
  anonymousCredentialIssuer: false,
  eligibilityProofVerifier: false,
  encryptedBallot: false,
  ballotValidityProof: false,
  tallyProofVerifier: false,
  votingEnabled: false
});

const requestCounts = new Map();
const WINDOW_MS = 60_000;
let rateLimitCalls = 0;
function rateLimit(req, key, max = 12) {
  const now = Date.now();
  if (++rateLimitCalls % 256 === 0) {
    for (const [entryKey, entry] of requestCounts) if (now - entry.startedAt > WINDOW_MS) requestCounts.delete(entryKey);
  }
  const requestKey = `${key}:${req.socket.remoteAddress ?? "unknown"}`;
  const old = requestCounts.get(requestKey);
  if (!old || now - old.startedAt > WINDOW_MS) {
    requestCounts.set(requestKey, { startedAt: now, count: 1 });
    return;
  }
  old.count += 1;
  if (old.count > max) {
    const error = new Error("Too many requests. Wait a minute and try again.");
    error.status = 429;
    throw error;
  }
}

function json(res, status, value, extraHeaders = {}) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    ...extraHeaders
  });
  res.end(body);
}

async function readJson(req) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (Buffer.byteLength(raw) > 64 * 1024) {
      const error = new Error("Request body is too large.");
      error.status = 413;
      throw error;
    }
  }
  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    const error = new Error("Request body must be valid JSON.");
    error.status = 400;
    throw error;
  }
}

function validateOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return;
  const expected = `${isProduction ? "https" : "http"}://${req.headers.host}`;
  if (origin !== expected) {
    const error = new Error("Cross-origin request rejected.");
    error.status = 403;
    throw error;
  }
}

async function readAuditLog() {
  const [valid, rows] = await Promise.all([
    rpc("audit_chain_is_valid", {}),
    supabaseRequest("audit_events?select=event_sequence,actor_kind,actor_user_id,actor_label,action_code,subject_voter_id,subject_election_id,subject_candidate_id,subject_challenge_id,occurred_at&order=event_sequence.desc&limit=100")
  ]);
  const logs = (rows ?? []).map((row) => {
    const subjectId = row.subject_voter_id ?? row.subject_election_id ?? row.subject_candidate_id ?? row.subject_challenge_id ?? "—";
    return {
      id: row.event_sequence,
      actor: row.actor_label ?? row.actor_user_id ?? row.actor_kind,
      action: row.action_code,
      subject: subjectId,
      createdAt: row.occurred_at
    };
  });
  return { valid: valid === true, logs };
}

async function handle(req, res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy", `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ${supabaseOrigin}; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`);

  const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
  const route = url.pathname;
  const method = req.method ?? "GET";

  if (route.startsWith("/api/") && method !== "GET" && method !== "HEAD") validateOrigin(req);

  if (method === "GET" && route === "/api/health") {
    return json(res, 200, {
      status: "ok",
      project: "Privacy-Preserving E-Voting Prototype",
      database: "supabase-postgres",
      crypto: cryptoReadiness,
      ballotSubmission: "disabled"
    });
  }

  if (method === "GET" && route === "/api/auth/config") {
    const configured = Boolean(supabasePublishableKey && voterEmailDomains.length);
    return json(res, 200, {
      configured,
      supabaseUrl,
      publishableKey: configured ? supabasePublishableKey : null,
      allowedEmailDomains: voterEmailDomains
    });
  }

  if (method === "GET" && route === "/api/auth/voter") {
    const authUser = await requireVerifiedVoterAuth(req);
    const rows = await supabaseRequest(`voters?select=voter_id,organization_id,full_name,email,registration_status,email_verified_at,created_at&auth_user_id=eq.${encodeURIComponent(authUser.id)}&limit=1`);
    const row = rows?.[0];
    const semaphoreIssuances = row?.registration_status === "approved"
      ? await supabaseRequest(`semaphore_credential_issuances?select=election_id&voter_id=eq.${encodeURIComponent(row.voter_id)}`)
      : [];
    return json(res, 200, {
      voter: row ? {
        id: row.voter_id,
        organizationId: row.organization_id,
        fullName: row.full_name,
        email: row.email,
        status: row.registration_status,
        emailVerified: Boolean(row.email_verified_at),
        createdAt: row.created_at,
        semaphoreCredentialElectionIds: (semaphoreIssuances ?? []).map((item) => item.election_id)
      } : null
    });
  }

  if (method === "GET" && route === "/api/elections") {
    return json(res, 200, { elections: await listElections(false) });
  }

  const uuidPattern = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
  const electionMatch = route.match(new RegExp(`^/api/elections/(${uuidPattern})$`));
  if (method === "GET" && electionMatch) {
    const election = await getElection(electionMatch[1]);
    return election && election.status !== "draft" ? json(res, 200, { election }) : json(res, 404, { error: "Election not found." });
  }

  const acceptedBallotsMatch = route.match(new RegExp(`^/api/elections/(${uuidPattern})/accepted-ballots$`));
  if (method === "GET" && acceptedBallotsMatch) {
    const election = await getElection(acceptedBallotsMatch[1]);
    if (!election || election.status === "draft") return json(res, 404, { error: "Election not found." });
    if (!election.semaphoreGroupFrozenAt || !election.semaphoreGroupRoot) {
      return json(res, 409, { error: "Public ballot export is available after voter registration closes and the Semaphore group is frozen." });
    }
    const [commitments, headRows] = await Promise.all([
      readSemaphoreCommitments(election.id),
      supabaseRequest(`election_ballot_chain_heads?select=last_sequence,last_hash&election_id=eq.${encodeURIComponent(election.id)}&limit=1`)
    ]);
    const ballots = [];
    for (let offset = 0; ; offset += 500) {
      const rows = await supabaseRequest(`accepted_ballots?select=election_id,ballot_sequence,ballot_id,ballot_hash,ballot_payload,semaphore_proof_hash,nullifier,accepted_at,previous_hash,record_hash&election_id=eq.${encodeURIComponent(election.id)}&order=ballot_sequence.asc&limit=500&offset=${offset}`);
      ballots.push(...(rows ?? []).map((row) => ({
        electionId: row.election_id,
        ballotSequence: String(row.ballot_sequence),
        ballotId: row.ballot_id,
        ballotHash: hashFromBytea(row.ballot_hash),
        ballotPayload: row.ballot_payload,
        semaphoreProofHash: hashFromBytea(row.semaphore_proof_hash),
        nullifier: String(row.nullifier),
        acceptedAt: row.accepted_at,
        previousHash: hashFromBytea(row.previous_hash),
        recordHash: hashFromBytea(row.record_hash)
      })));
      if (!rows || rows.length < 500) break;
    }
    const head = headRows?.[0];
    return json(res, 200, {
      version: 1,
      election,
      semaphoreCommitments: commitments,
      ballots,
      chainHead: head
        ? { lastSequence: String(head.last_sequence), lastHash: hashFromBytea(head.last_hash) }
        : { lastSequence: 0, lastHash: "00".repeat(32) }
    });
  }

  const semaphoreGroupMatch = route.match(new RegExp(`^/api/elections/(${uuidPattern})/semaphore-group$`));
  if (method === "GET" && semaphoreGroupMatch) {
    const election = await getElection(semaphoreGroupMatch[1]);
    if (!election || election.status === "draft") return json(res, 404, { error: "Election not found." });
    if (!election.semaphoreGroupFrozenAt || !election.semaphoreGroupRoot) {
      return json(res, 409, { error: "The Semaphore group is not public until voter registration closes." });
    }
    const commitments = await readSemaphoreCommitments(election.id);
    const group = createSemaphoreGroup(commitments, { minimumMembers: 0 });
    if (election.semaphoreGroupFrozenAt && election.semaphoreGroupRoot !== group.root.toString()) {
      throw new Error("Stored Semaphore group root does not match the member list.");
    }
    return json(res, 200, {
      electionId: election.id,
      commitments,
      count: commitments.length,
      root: group.root.toString(),
      depth: group.depth,
      frozenAt: election.semaphoreGroupFrozenAt,
      proofAvailable: commitments.length >= 3
    });
  }

  const freezeSemaphoreMatch = route.match(new RegExp(`^/api/admin/elections/(${uuidPattern})/freeze-semaphore-group$`));
  if (method === "POST" && freezeSemaphoreMatch) {
    const admin = requireAdmin(req);
    const election = await getElection(freezeSemaphoreMatch[1]);
    if (!election) return json(res, 404, { error: "Election not found." });
    const commitments = await readSemaphoreCommitments(election.id, true);
    if (commitments.length < 3) return json(res, 409, { error: "Enroll at least three approved voters before freezing the group." });
    const randomizedCommitments = shuffleCommitments(commitments);
    const group = createSemaphoreGroup(randomizedCommitments);
    const result = await rpc("freeze_semaphore_group", {
      p_election_id: election.id,
      p_group_root: group.root.toString(),
      p_commitments: randomizedCommitments,
      p_admin_email: admin.email
    });
    if (!result?.found) return json(res, 404, { error: "Election not found." });
    if (result.open === false) return json(res, 409, { error: "The Semaphore group can only be frozen before the scheduled start." });
    if (result.valid === false || result.same_root === false) return json(res, 409, { error: "Group membership changed or the computed root is invalid. Refresh and try again before the election starts." });
    return json(res, 200, {
      electionId: election.id,
      root: group.root.toString(),
      count: randomizedCommitments.length,
      frozen: true
    });
  }

  const semaphoreIdentityMatch = route.match(new RegExp(`^/api/elections/(${uuidPattern})/semaphore-identity$`));
  if (method === "POST" && semaphoreIdentityMatch) {
    rateLimit(req, "semaphore-identity-issuance", 3);
    const authUser = await requireVerifiedVoterAuth(req);
    const body = await readJson(req);
    const commitment = String(body.commitment ?? "");
    if (!/^[1-9][0-9]{0,76}$/.test(commitment)) {
      return json(res, 400, { error: "Provide a valid Semaphore identity commitment." });
    }
    const result = await rpc("issue_semaphore_identity", {
      p_election_id: semaphoreIdentityMatch[1],
      p_auth_user_id: authUser.id,
      p_commitment: commitment
    });
    if (!result?.found) return json(res, 404, { error: "Election not found." });
    if (result.invalid_commitment) return json(res, 400, { error: "The Semaphore commitment is outside the allowed field." });
    if (result.open === false) return json(res, 409, { error: "Identity enrollment is closed. Register before the scheduled election starts." });
    if (result.eligible === false && result.already_issued) return json(res, 409, { error: "An identity was already issued for this election. Restore the encrypted identity vault instead of creating another." });
    if (result.eligible === false && result.duplicate_commitment) return json(res, 409, { error: "This identity is already in the election group." });
    if (result.eligible === false) return json(res, 403, { error: "An email-verified, registrar-approved voter registration is required." });
    return json(res, result.retry ? 200 : 201, { registered: true, retry: Boolean(result.retry) });
  }

  if (method === "POST" && route === "/api/auth/register") {
    rateLimit(req, "voter-registration", 5);
    const authUser = await requireVerifiedVoterAuth(req);
    const body = await readJson(req);
    const fullName = String(body.fullName ?? "").trim();
    const organizationId = String(body.organizationId ?? "").trim();
    if (fullName.length < 2 || fullName.length > 120 || organizationId.length < 3 || organizationId.length > 80) {
      return json(res, 400, { error: "Enter your full name and valid university student ID." });
    }
    const result = await rpc("register_authenticated_voter", {
      p_auth_user_id: authUser.id,
      p_organization_id: organizationId,
      p_full_name: fullName,
      p_email: authUser.email
    });
    if (!result?.ok) return json(res, 409, { error: "This student ID or account is already linked to a different voter registration." });
    return json(res, result.created ? 201 : 200, {
      voterId: result.voter_id,
      status: result.status,
      message: result.created ? "Verified account linked. Your student eligibility is pending registrar review." : "Your voter registration is already on file."
    });
  }

  if (method === "POST" && route === "/api/admin/login") {
    rateLimit(req, "admin-login", 8);
    const body = await readJson(req);
    const email = String(body.email ?? "").trim().toLowerCase();
    const password = String(body.password ?? "");
    const candidate = passwordHash(password, adminSalt);
    if (!safeEqual(email, adminEmail) || !safeEqual(candidate, configuredAdminPasswordHash)) return json(res, 401, { error: "Email or password is incorrect." });
    const token = tokenFor({ sub: adminEmail, email: adminEmail, role: "admin" });
    await rpc("audit_admin_event", { p_admin_email: adminEmail, p_action_code: "admin.login" });
    setSessionCookie(res, token);
    return json(res, 200, { signedIn: true, email: adminEmail });
  }

  if (method === "POST" && route === "/api/admin/logout") {
    const session = sessionFor(req);
    if (session) await rpc("audit_admin_event", { p_admin_email: session.email, p_action_code: "admin.logout" });
    clearSessionCookie(res);
    return json(res, 200, { signedIn: false });
  }

  if (method === "GET" && route === "/api/admin/overview") {
    const admin = requireAdmin(req);
    const voters = await supabaseRequest("voters?select=registration_status,email_verified_at");
    const counts = (voters ?? []).reduce((result, voter) => {
      result.registered += 1;
      if (voter.registration_status === "approved") result.approved += 1;
      if (voter.email_verified_at) result.emailVerified += 1;
      return result;
    }, { registered: 0, approved: 0, emailVerified: 0 });
    return json(res, 200, { admin: { email: admin.email }, counts, crypto: cryptoReadiness });
  }

  if (method === "GET" && route === "/api/admin/voters") {
    requireAdmin(req);
    const rows = await supabaseRequest("voters?select=voter_id,full_name,organization_id,email,registration_status,email_verified_at,created_at&order=created_at.desc");
    const voters = (rows ?? []).map((voter) => ({
      id: voter.voter_id,
      fullName: voter.full_name,
      organizationId: voter.organization_id,
      email: voter.email,
      status: voter.registration_status,
      emailVerified: Boolean(voter.email_verified_at),
      credentialIssued: false,
      createdAt: voter.created_at
    }));
    return json(res, 200, { voters });
  }

  if (method === "GET" && route === "/api/admin/elections") {
    requireAdmin(req);
    return json(res, 200, { elections: await listElections(true) });
  }

  const reopenForKeySetupMatch = route.match(new RegExp(`^/api/admin/elections/(${uuidPattern})/reopen-for-key-setup$`));
  if (method === "POST" && reopenForKeySetupMatch) {
    const admin = requireAdmin(req);
    const electionId = reopenForKeySetupMatch[1];
    const result = await rpc("reopen_election_for_key_setup", {
      p_election_id: electionId,
      p_admin_email: admin.email
    });
    if (!result?.found) return json(res, 404, { error: "Election not found." });
    if (!result.ready) {
      const errors = {
        key_configured: "An election key is already configured; reopening is refused.",
        group_frozen: "A frozen Semaphore group exists; reopening is refused.",
        already_started: "This election has started; reopening is refused.",
        activity_exists: "Ballots, voter enrollments, a contract deployment, or a tally exist; reopening is refused.",
        not_scheduled: "Only a scheduled election with a cleared manifest can be reopened for key setup."
      };
      return json(res, 409, { error: errors[result.reason] ?? "This election cannot be reopened for key setup." });
    }
    return json(res, 200, {
      electionId,
      status: "draft",
      reopened: Boolean(result.reopened),
      republishRequired: true
    });
  }

  const voterDecisionMatch = route.match(new RegExp(`^/api/admin/voters/(${uuidPattern})/(approve|reject)$`));
  if (method === "POST" && voterDecisionMatch) {
    const admin = requireAdmin(req);
    const voterId = voterDecisionMatch[1];
    const decision = voterDecisionMatch[2] === "approve" ? "approved" : "rejected";
    const result = await rpc("review_voter_registration", {
      p_voter_id: voterId,
      p_decision: decision,
      p_admin_email: admin.email
    });
    if (!result?.found) return json(res, 404, { error: "Voter not found." });
    if (result.verified === false) return json(res, 409, { error: "The voter must have a confirmed email before eligibility can be approved." });
    if (!result.changed) return json(res, 409, { error: "This registration has already been reviewed." });
    return json(res, 200, { voterId, status: decision });
  }

  if (method === "POST" && route === "/api/admin/elections") {
    const admin = requireAdmin(req);
    const body = await readJson(req);
    const title = String(body.title ?? "").trim();
    const description = String(body.description ?? "").trim();
    if (title.length < 4 || title.length > 160 || description.length > 1000 || typeof body.startsAt !== "string" || typeof body.endsAt !== "string") {
      return json(res, 400, { error: "Provide a title, description, and valid start and end dates." });
    }
    const startsDate = new Date(body.startsAt);
    const endsDate = new Date(body.endsAt);
    if (!Number.isFinite(startsDate.getTime()) || !Number.isFinite(endsDate.getTime())) {
      return json(res, 400, { error: "Start and end dates must be valid." });
    }
    const startsAt = startsDate.toISOString();
    const endsAt = endsDate.toISOString();
    const candidates = Array.isArray(body.candidates) ? body.candidates : [];
    if (candidates.length < 2 || candidates.length > 20 || candidates.some((candidate) => !candidate || typeof candidate !== "object" || String(candidate.name ?? "").trim().length < 2 || String(candidate.name ?? "").trim().length > 100 || String(candidate.manifesto ?? "").trim().length > 1000)) {
      return json(res, 400, { error: "Provide between 2 and 20 candidates. Names must be 2–100 characters and statements at most 1,000 characters." });
    }
    if (new Date(startsAt).getTime() >= new Date(endsAt).getTime()) return json(res, 400, { error: "The end time must be later than the start time." });
    const electionId = await rpc("create_election_with_candidates", {
      p_title: title,
      p_description: description,
      p_starts_at: startsAt,
      p_ends_at: endsAt,
      p_candidates: candidates.map((candidate) => ({
        name: String(candidate.name).trim(),
        manifesto: String(candidate.manifesto ?? "").trim()
      })),
      p_admin_email: admin.email
    });
    const election = await getElection(electionId);
    return json(res, 201, { election });
  }

  const keySetupMatch = route.match(new RegExp(`^/api/admin/elections/(${uuidPattern})/prototype-key$`));
  if (method === "POST" && keySetupMatch) {
    const admin = requireAdmin(req);
    const election = await getElection(keySetupMatch[1]);
    if (!election) return json(res, 404, { error: "Election not found." });
    if (election.status !== "draft") return json(res, 409, { error: "Election keys can only be configured before publication." });
    if (election.electionPublicKey || election.keyCeremonyStatus !== "not_started") {
      return json(res, 409, { error: "This election already has an assigned key. Key replacement is refused." });
    }
    const body = await readJson(req);
    const publicKey = String(body.publicKey ?? "");
    if (!isValidElectionPublicKey(publicKey)) {
      return json(res, 400, { error: "Provide a valid canonical Ristretto255 election public key." });
    }
    const result = await rpc("configure_prototype_election_key", {
      p_election_id: keySetupMatch[1],
      p_public_key: publicKey,
      p_admin_email: admin.email
    });
    if (!result?.found) return json(res, 404, { error: "Election not found." });
    if (!result.draft) return json(res, 409, { error: "Election keys can only be configured before publication." });
    if (result.already_configured || !result.configured) return json(res, 409, { error: "This election already has an assigned key. Key replacement is refused." });
    return json(res, 200, {
      electionId: keySetupMatch[1],
      electionPublicKey: publicKey,
      keyCeremonyStatus: "prototype_single_key"
    });
  }

  const publishMatch = route.match(new RegExp(`^/api/admin/elections/(${uuidPattern})/publish$`));
  if (method === "POST" && publishMatch) {
    const admin = requireAdmin(req);
    const id = publishMatch[1];
    const election = await getElection(id);
    if (!election) return json(res, 404, { error: "Election not found." });
    if (election.status !== "draft") return json(res, 409, { error: "Only draft elections can be published." });
    if (election.candidates.length < 2) return json(res, 409, { error: "Add at least two candidates before publishing." });
    if (!election.electionPublicKey || election.keyCeremonyStatus !== "prototype_single_key") {
      return json(res, 409, { error: "Generate the prototype election key before freezing and publishing this election." });
    }
    if (new Date(election.startsAt).getTime() <= Date.now()) {
      return json(res, 409, { error: "Publish before the election opens so eligible students can enroll in the anonymous group." });
    }
    const status = "scheduled";
    const manifestHash = hash(canonicalManifest(election, election.candidates));
    const result = await rpc("publish_election", {
      p_election_id: id,
      p_status: status,
      p_manifest_hash_hex: manifestHash,
      p_admin_email: admin.email
    });
    if (!result?.found) return json(res, 404, { error: "Election not found." });
    if (!result.draft) return json(res, 409, { error: "Only draft elections can be published." });
    if (!result.complete) return json(res, 409, { error: "Add at least two candidates before publishing." });
    if (result.key_configured === false) return json(res, 409, { error: "Generate the prototype election key before freezing and publishing this election." });
    return json(res, 200, { election: await getElection(id) });
  }

  if (method === "GET" && route === "/api/admin/audit-logs") {
    requireAdmin(req);
    return json(res, 200, await readAuditLog());
  }

  if (method === "POST" && route === "/api/vote/relay") {
    if (process.env.ENABLE_BALLOT_ACCEPTANCE !== "true" || !cryptoReadiness.votingEnabled) {
      return json(res, 503, { error: "Ballot submission is disabled until every cryptographic and election-readiness gate has passed." });
    }
    const body = await readJson(req);
    const election = await getElection(String(body.electionId ?? ""));
    if (!election) return json(res, 404, { error: "Election not found." });
    if (!election.semaphoreGroupFrozenAt || !election.semaphoreGroupRoot) {
      return json(res, 409, { error: "The anonymous eligibility group must be frozen before voting." });
    }
    const commitments = await readSemaphoreCommitments(election.id);
    const group = createSemaphoreGroup(commitments);
    if (group.root.toString() !== election.semaphoreGroupRoot) {
      return json(res, 409, { error: "The frozen anonymous eligibility group no longer matches its published root." });
    }
    const eligibilityValid = await verifySemaphoreProofForBallot(
      body.semaphoreProof,
      election.id,
      body.ballot?.ballotHash,
      commitments
    );
    if (!eligibilityValid || body.nullifier !== body.semaphoreProof?.nullifier) {
      return json(res, 400, { error: "invalid_eligibility_proof" });
    }
    const result = await acceptVerifiedBallot(
      body.ballot,
      election,
      ({ electionId, ballotHash }) => rpc("record_accepted_ballot", {
        p_election_id: electionId,
        p_ballot_id: body.ballot.ballotId,
        p_ballot_hash_hex: ballotHash,
        p_nullifier: body.nullifier,
        p_semaphore_proof_hash_hex: hash(canonicalJson(body.semaphoreProof)),
        p_ballot_payload: body
      }),
      { nullifier: body.nullifier }
    );
    if (!result.valid) {
      const status = result.reason === "election_closed" || result.reason === "replayed_ballot" ? 409 : 400;
      return json(res, status, { error: result.reason });
    }
    try {
      const relay = await relayVerifiedBallot({ election, ballot: body.ballot, nullifier: body.nullifier });
      await rpc("mark_ballot_relayed", {
        p_election_id: election.id,
        p_ballot_sequence: result.record.ballot_sequence,
        p_transaction_hash: relay.transactionHash
      });
      return json(res, 202, {
        accepted: true,
        ballotHash: result.ballotHash,
        ballotSequence: result.record.ballot_sequence,
        relayStatus: "relayed",
        transactionHash: relay.transactionHash
      });
    } catch {
      return json(res, 202, {
        accepted: true,
        ballotHash: result.ballotHash,
        ballotSequence: result.record.ballot_sequence,
        relayStatus: "pending",
        retryable: true
      });
    }
  }

  if (route.startsWith("/api/")) return json(res, 404, { error: "API route not found." });

  if (method !== "GET" && method !== "HEAD") return json(res, 405, { error: "Method not allowed." });
  let filePath = path.resolve(publicDir, `.${decodeURIComponent(route)}`);
  if (route === "/") filePath = path.join(publicDir, "index.html");
  if (!filePath.startsWith(publicDir + path.sep) && filePath !== path.join(publicDir, "index.html")) {
    return json(res, 404, { error: "Not found." });
  }
  if (!existsSync(filePath)) return json(res, 404, { error: "Not found." });
  const contentTypes = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml"
  };
  const content = readFileSync(filePath);
  res.writeHead(200, {
    "Content-Type": contentTypes[path.extname(filePath)] ?? "application/octet-stream",
    "Content-Length": content.length,
    "Cache-Control": "no-cache"
  });
  res.end(method === "HEAD" ? undefined : content);
}

const server = createServer((req, res) => {
  handle(req, res).catch((error) => {
    const status = Number(error.status) || 500;
    if (status === 500) console.error("Request failed; request and identity data redacted.");
    if (!res.headersSent) json(res, status, { error: status === 500 ? "An internal error occurred." : error.message });
    else res.destroy();
  });
});

const port = Number(process.env.PORT ?? 4173);
const host = process.env.HOST ?? "127.0.0.1";
await verifySupabaseConnection();
server.listen(port, host, () => {
  const displayHost = host === "0.0.0.0" || host === "::" ? "0.0.0.0" : host;
  console.log(`Voting prototype listening at http://${displayHost}:${port}`);
  console.log("Database: Supabase Postgres");
  console.log("Ballot submission remains disabled pending independent review and deployment checks.");
});

function shutdown() {
  server.close(() => process.exit(0));
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
