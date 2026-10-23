import { createServer } from "node:http";
import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual
} from "node:crypto";
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
if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error("Set SUPABASE_URL and a server-only SUPABASE_SECRET_KEY (or legacy SUPABASE_SERVICE_ROLE_KEY) in .env.");
}
if (isProduction) {
  const required = ["ADMIN_EMAIL", "ADMIN_PASSWORD", "JWT_SECRET", "OTP_SECRET", "SUPABASE_URL"];
  const missing = required.filter((key) => !process.env[key]);
  const secretNames = ["JWT_SECRET", "OTP_SECRET"];
  const weakSecrets = secretNames.filter((key) => (process.env[key] ?? "").length < 32 || /replace-with|change-this/i.test(process.env[key] ?? ""));
  const distinctSecrets = new Set(secretNames.map((key) => process.env[key])).size === secretNames.length;
  if (missing.length || weakSecrets.length || !distinctSecrets || (process.env.ADMIN_PASSWORD ?? "").length < 14 || /change-|replace-with/i.test(process.env.ADMIN_PASSWORD ?? "")) {
    throw new Error("Production requires ADMIN_EMAIL, a non-placeholder ADMIN_PASSWORD of at least 14 characters, and distinct non-placeholder JWT_SECRET and OTP_SECRET values of at least 32 characters each.");
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
for (const key of ["JWT_SECRET", "OTP_SECRET"]) {
  if (!process.env[key] && (typeof localSecrets[key] !== "string" || !/^[0-9a-f]{64}$/i.test(localSecrets[key]))) {
    localSecrets[key] = randomBytes(32).toString("hex");
    localSecretChanged = true;
  }
}
if (localSecretChanged) writeFileSync(localSecretPath, `${JSON.stringify(localSecrets, null, 2)}\n`, secretFileExisted ? {} : { flag: "wx", mode: 0o600 });
const jwtSecret = process.env.JWT_SECRET || localSecrets.JWT_SECRET;
const otpSecret = process.env.OTP_SECRET || localSecrets.OTP_SECRET;

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
  return JSON.stringify({
    electionId: String(election.id ?? election.election_id),
    title: election.title,
    description: election.description,
    startsAt: new Date(election.startsAt ?? election.starts_at).toISOString(),
    endsAt: new Date(election.endsAt ?? election.ends_at).toISOString(),
    candidates: candidates.map((item, index) => ({
      position: index + 1,
      name: item.name ?? item.display_name,
      manifesto: item.manifesto
    }))
  });
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
    status: row.status,
    candidates: candidateList
  };
  election.manifestHash = hashFromBytea(row.manifest_hash) ?? hash(canonicalManifest(election, candidateList));
  return election;
}

async function getElection(id) {
  const rows = await supabaseRequest(`elections?select=election_id,title,description,starts_at,ends_at,status,manifest_hash&election_id=eq.${encodeURIComponent(id)}&limit=1`);
  const row = rows?.[0];
  if (!row) return null;
  const candidates = await supabaseRequest(`candidates?select=candidate_id,display_name,manifesto,list_order&election_id=eq.${encodeURIComponent(id)}&order=list_order.asc`);
  return mapElectionRow(row, candidates ?? []);
}

async function listElections(includeDrafts = false) {
  const statusFilter = includeDrafts ? "" : "&status=neq.draft";
  const rows = await supabaseRequest(`elections?select=election_id,title,description,starts_at,ends_at,status,manifest_hash&order=created_at.desc${statusFilter}`);
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
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");

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

  if (method === "GET" && route === "/api/elections") {
    return json(res, 200, { elections: await listElections(false) });
  }

  const uuidPattern = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
  const electionMatch = route.match(new RegExp(`^/api/elections/(${uuidPattern})$`));
  if (method === "GET" && electionMatch) {
    const election = await getElection(electionMatch[1]);
    return election && election.status !== "draft" ? json(res, 200, { election }) : json(res, 404, { error: "Election not found." });
  }

  if (method === "POST" && route === "/api/auth/register") {
    rateLimit(req, "register", 5);
    const body = await readJson(req);
    const fullName = String(body.fullName ?? "").trim();
    const organizationId = String(body.organizationId ?? "").trim();
    const email = String(body.email ?? "").trim().toLowerCase();
    if (fullName.length < 2 || fullName.length > 120 || organizationId.length < 3 || organizationId.length > 80 || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return json(res, 400, { error: "Enter your name, organization ID, and a valid email address." });
    }
    if (isProduction) return json(res, 503, { error: "OTP delivery is not configured. Registration is unavailable." });
    const otp = String(randomBytes(4).readUInt32BE() % 1_000_000).padStart(6, "0");
    const otpHash = createHmac("sha256", otpSecret).update(`${organizationId}:${otp}`).digest("hex");
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const result = await rpc("register_voter", {
      p_organization_id: organizationId,
      p_full_name: fullName,
      p_email: email,
      p_secret_hash_hex: otpHash,
      p_expires_at: expiresAt
    });
    if (!result?.ok) return json(res, 409, { error: "A registration already exists for this organization ID." });
    return json(res, result.created ? 201 : 200, {
      voterId: result.voter_id,
      message: "Demo OTP created. This development build shows it below; no email is sent.",
      demoOtp: otp,
      expiresAt
    });
  }

  if (method === "POST" && route === "/api/auth/verify-otp") {
    rateLimit(req, "verify-otp", 10);
    const body = await readJson(req);
    const organizationId = String(body.organizationId ?? "").trim();
    const otp = String(body.otp ?? "").trim();
    if (!/^\d{6}$/.test(otp) || !organizationId) return json(res, 400, { error: "The code is invalid or has expired." });
    const providedHash = createHmac("sha256", otpSecret).update(`${organizationId}:${otp}`).digest("hex");
    const result = await rpc("verify_voter_otp", {
      p_organization_id: organizationId,
      p_secret_hash_hex: providedHash
    });
    if (!result?.ok) return json(res, 400, { error: "The code is invalid or has expired." });
    return json(res, 200, {
      verified: true,
      status: result.status,
      message: result.status === "approved" ? "Identity channel verified." : "Identity channel verified. Eligibility still requires registrar approval."
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
      if (voter.email_verified_at) result.otpVerified += 1;
      return result;
    }, { registered: 0, approved: 0, otpVerified: 0 });
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
      otpVerified: Boolean(voter.email_verified_at),
      credentialIssued: false,
      createdAt: voter.created_at
    }));
    return json(res, 200, { voters });
  }

  if (method === "GET" && route === "/api/admin/elections") {
    requireAdmin(req);
    return json(res, 200, { elections: await listElections(true) });
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
    if (result.verified === false) return json(res, 409, { error: "Verify the voter’s email or phone before approving eligibility." });
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

  const publishMatch = route.match(new RegExp(`^/api/admin/elections/(${uuidPattern})/publish$`));
  if (method === "POST" && publishMatch) {
    const admin = requireAdmin(req);
    const id = publishMatch[1];
    const election = await getElection(id);
    if (!election) return json(res, 404, { error: "Election not found." });
    if (election.status !== "draft") return json(res, 409, { error: "Only draft elections can be published." });
    if (election.candidates.length < 2) return json(res, 409, { error: "Add at least two candidates before publishing." });
    const now = Date.now();
    const status = new Date(election.endsAt).getTime() <= now ? "closed" : new Date(election.startsAt).getTime() <= now ? "active" : "scheduled";
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
    return json(res, 200, { election: await getElection(id) });
  }

  if (method === "GET" && route === "/api/admin/audit-logs") {
    requireAdmin(req);
    return json(res, 200, await readAuditLog());
  }

  if (method === "POST" && route === "/api/vote/relay") {
    return json(res, 503, { error: "Ballot submission is disabled until audited anonymous-credential, ballot-encryption, and proof-verification components are configured." });
  }

  if (route.startsWith("/api/")) return json(res, 404, { error: "API route not found." });

  if (method !== "GET" && method !== "HEAD") return json(res, 405, { error: "Method not allowed." });
  let filePath = path.resolve(publicDir, `.${decodeURIComponent(route)}`);
  if (!filePath.startsWith(publicDir + path.sep) && filePath !== path.join(publicDir, "index.html")) {
    return json(res, 404, { error: "Not found." });
  }
  if (route === "/") filePath = path.join(publicDir, "index.html");
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
    if (status === 500) console.error("Request failed:", error.message);
    if (!res.headersSent) json(res, status, { error: status === 500 ? "An internal error occurred." : error.message });
    else res.destroy();
  });
});

const port = Number(process.env.PORT ?? 4173);
await verifySupabaseConnection();
server.listen(port, "127.0.0.1", () => {
  console.log(`Voting prototype available at http://localhost:${port}`);
  console.log("Database: Supabase Postgres");
  console.log("Cryptographic voting submission is disabled until real verifiers are configured.");
});

function shutdown() {
  server.close(() => process.exit(0));
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
