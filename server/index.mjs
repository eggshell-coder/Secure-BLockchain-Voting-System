import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
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
if (isProduction) {
  const required = ["ADMIN_EMAIL", "ADMIN_PASSWORD", "JWT_SECRET", "AUDIT_SECRET", "OTP_SECRET"];
  const missing = required.filter((key) => !process.env[key]);
  const secretNames = ["JWT_SECRET", "AUDIT_SECRET", "OTP_SECRET"];
  const weakSecrets = secretNames.filter((key) => (process.env[key] ?? "").length < 32 || /replace-with|change-this/i.test(process.env[key] ?? ""));
  const distinctSecrets = new Set(secretNames.map((key) => process.env[key])).size === secretNames.length;
  if (missing.length || weakSecrets.length || !distinctSecrets || (process.env.ADMIN_PASSWORD ?? "").length < 14 || /change-|replace-with/i.test(process.env.ADMIN_PASSWORD ?? "")) {
    throw new Error("Production requires ADMIN_EMAIL, a non-placeholder ADMIN_PASSWORD of at least 14 characters, and unique non-placeholder JWT_SECRET, AUDIT_SECRET, and OTP_SECRET values of at least 32 characters each.");
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
for (const key of ["JWT_SECRET", "AUDIT_SECRET", "OTP_SECRET"]) {
  if (!process.env[key] && (typeof localSecrets[key] !== "string" || !/^[0-9a-f]{64}$/i.test(localSecrets[key]))) {
    localSecrets[key] = randomBytes(32).toString("hex");
    localSecretChanged = true;
  }
}
if (localSecretChanged) writeFileSync(localSecretPath, `${JSON.stringify(localSecrets, null, 2)}\n`, secretFileExisted ? {} : { flag: "wx", mode: 0o600 });
const jwtSecret = process.env.JWT_SECRET || localSecrets.JWT_SECRET;
const auditSecret = process.env.AUDIT_SECRET || localSecrets.AUDIT_SECRET;
const otpSecret = process.env.OTP_SECRET || localSecrets.OTP_SECRET;
const db = new DatabaseSync(path.join(dataDir, "voting.sqlite"));
db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS voters (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    organization_id TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    otp_hash TEXT,
    otp_expires_at TEXT,
    otp_attempts INTEGER NOT NULL DEFAULT 0,
    otp_verified INTEGER NOT NULL DEFAULT 0,
    credential_issued INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS elections (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    manifest_hash TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY,
    election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    manifesto TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
  );
`);

const voterColumns = new Set(db.prepare("PRAGMA table_info(voters)").all().map((column) => column.name));
if (!voterColumns.has("otp_attempts")) db.exec("ALTER TABLE voters ADD COLUMN otp_attempts INTEGER NOT NULL DEFAULT 0");

function isoNow() {
  return new Date().toISOString();
}

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

function recordAudit(actor, action, subject) {
  const previous = db.prepare("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").get()?.entry_hash ?? "0".repeat(64);
  const createdAt = isoNow();
  const message = JSON.stringify({ actor, action, subject, createdAt, previous });
  const entryHash = createHmac("sha256", auditSecret).update(message).digest("hex");
  db.prepare(`INSERT INTO audit_logs(actor, action, subject, created_at, previous_hash, entry_hash)
    VALUES (?, ?, ?, ?, ?, ?)`)
    .run(actor, action, subject, createdAt, previous, entryHash);
}

function transaction(work) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = work();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function canonicalManifest(election, candidates) {
  return JSON.stringify({
    electionId: Number(election.id),
    title: election.title,
    description: election.description,
    startsAt: election.starts_at,
    endsAt: election.ends_at,
    candidates: candidates.map((item, index) => ({
      position: index + 1,
      name: item.name,
      manifesto: item.manifesto
    }))
  });
}

function getElection(id) {
  const election = db.prepare("SELECT * FROM elections WHERE id = ?").get(id);
  if (!election) return null;
  const candidates = db.prepare("SELECT id, name, manifesto FROM candidates WHERE election_id = ? ORDER BY id").all(id);
  const computedHash = hash(canonicalManifest(election, candidates));
  return {
    id: Number(election.id),
    title: election.title,
    description: election.description,
    startsAt: election.starts_at,
    endsAt: election.ends_at,
    status: election.status,
    manifestHash: election.manifest_hash ?? computedHash,
    candidates
  };
}

function seedData() {
  const adminCount = db.prepare("SELECT COUNT(*) AS count FROM admins").get().count;
  if (!adminCount) {
    const email = (process.env.ADMIN_EMAIL || "admin@demo.local").trim().toLowerCase();
    const password = process.env.ADMIN_PASSWORD || "change-me-now";
    const salt = randomBytes(16).toString("hex");
    db.prepare("INSERT INTO admins(email, salt, password_hash, created_at) VALUES (?, ?, ?, ?)")
      .run(email, salt, passwordHash(password, salt), isoNow());
  }

  const electionCount = db.prepare("SELECT COUNT(*) AS count FROM elections").get().count;
  if (!isProduction && !electionCount) {
    const startsAt = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const endsAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const result = db.prepare(`INSERT INTO elections(title, description, starts_at, ends_at, status, created_at)
      VALUES (?, ?, ?, ?, 'published', ?)`)
      .run("Sample Student Council Election", "Fictional demo election. Ballot submission remains locked until real cryptographic components are configured.", startsAt, endsAt, isoNow());
    const electionId = Number(result.lastInsertRowid);
    const insertCandidate = db.prepare("INSERT INTO candidates(election_id, name, manifesto) VALUES (?, ?, ?)");
    insertCandidate.run(electionId, "Candidate A", "A fictional candidate used only for local demonstration.");
    insertCandidate.run(electionId, "Candidate B", "A fictional candidate used only for local demonstration.");
    const election = db.prepare("SELECT * FROM elections WHERE id = ?").get(electionId);
    const candidates = db.prepare("SELECT id, name, manifesto FROM candidates WHERE election_id = ? ORDER BY id").all(electionId);
    db.prepare("UPDATE elections SET manifest_hash = ? WHERE id = ?").run(hash(canonicalManifest(election, candidates)), electionId);
  }
}

seedData();

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

function auditRows() {
  return db.prepare(`SELECT id, actor, action, subject, created_at AS createdAt,
    previous_hash AS previousHash, entry_hash AS entryHash FROM audit_logs ORDER BY id DESC LIMIT 100`).all();
}

function verifyAuditChain() {
  const rows = db.prepare("SELECT actor, action, subject, created_at AS createdAt, previous_hash AS previousHash, entry_hash AS entryHash FROM audit_logs ORDER BY id").all();
  let previous = "0".repeat(64);
  for (const row of rows) {
    if (row.previousHash !== previous) return false;
    const message = JSON.stringify({ actor: row.actor, action: row.action, subject: row.subject, createdAt: row.createdAt, previous });
    const expected = createHmac("sha256", auditSecret).update(message).digest("hex");
    if (!safeEqual(row.entryHash, expected)) return false;
    previous = row.entryHash;
  }
  return true;
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
      crypto: cryptoReadiness,
      ballotSubmission: "disabled"
    });
  }

  if (method === "GET" && route === "/api/elections") {
    const ids = db.prepare("SELECT id FROM elections WHERE status != 'draft' ORDER BY created_at DESC").all();
    return json(res, 200, { elections: ids.map((row) => getElection(row.id)).filter(Boolean) });
  }

  const electionMatch = route.match(/^\/api\/elections\/(\d+)$/);
  if (method === "GET" && electionMatch) {
    const election = getElection(Number(electionMatch[1]));
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
    const existing = db.prepare("SELECT id, otp_verified, status FROM voters WHERE organization_id = ?").get(organizationId);
    if (existing && (existing.otp_verified || existing.status !== "pending")) {
      return json(res, 409, { error: "A registration already exists for this organization ID." });
    }
    const otp = String(randomBytes(4).readUInt32BE() % 1_000_000).padStart(6, "0");
    const otpHash = createHmac("sha256", otpSecret).update(`${organizationId}:${otp}`).digest("hex");
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    let voterId;
    if (existing) {
      voterId = Number(existing.id);
      db.prepare(`UPDATE voters SET full_name = ?, email = ?, otp_hash = ?, otp_expires_at = ?, otp_attempts = 0
        WHERE id = ?`).run(fullName, email, otpHash, expiresAt, voterId);
    } else {
      const result = db.prepare(`INSERT INTO voters(full_name, organization_id, email, status, otp_hash, otp_expires_at, created_at)
        VALUES (?, ?, ?, 'pending', ?, ?, ?)`)
        .run(fullName, organizationId, email, otpHash, expiresAt, isoNow());
      voterId = Number(result.lastInsertRowid);
    }
    return json(res, existing ? 200 : 201, { voterId, message: "Demo OTP created. In this local build it is shown below.", demoOtp: otp, expiresAt });
  }

  if (method === "POST" && route === "/api/auth/verify-otp") {
    rateLimit(req, "verify-otp", 10);
    const body = await readJson(req);
    const organizationId = String(body.organizationId ?? "").trim();
    const otp = String(body.otp ?? "").trim();
    const voter = db.prepare("SELECT id, status, otp_hash, otp_expires_at, otp_attempts FROM voters WHERE organization_id = ?").get(organizationId);
    if (!voter || !voter.otp_hash || new Date(voter.otp_expires_at).getTime() < Date.now()) {
      return json(res, 400, { error: "The code is invalid or has expired." });
    }
    if (voter.otp_attempts >= 5) {
      db.prepare("UPDATE voters SET otp_hash = NULL, otp_expires_at = NULL WHERE id = ?").run(voter.id);
      return json(res, 400, { error: "The code is invalid or has expired." });
    }
    const providedHash = createHmac("sha256", otpSecret).update(`${organizationId}:${otp}`).digest("hex");
    if (!safeEqual(providedHash, voter.otp_hash)) {
      const attempts = voter.otp_attempts + 1;
      db.prepare("UPDATE voters SET otp_attempts = ?, otp_hash = CASE WHEN ? >= 5 THEN NULL ELSE otp_hash END, otp_expires_at = CASE WHEN ? >= 5 THEN NULL ELSE otp_expires_at END WHERE id = ?")
        .run(attempts, attempts, attempts, voter.id);
      return json(res, 400, { error: "The code is invalid or has expired." });
    }
    db.prepare("UPDATE voters SET otp_verified = 1, otp_hash = NULL, otp_expires_at = NULL, otp_attempts = 0 WHERE id = ?").run(voter.id);
    return json(res, 200, {
      verified: true,
      status: voter.status,
      message: voter.status === "approved" ? "Identity channel verified." : "Identity channel verified. Eligibility still requires registrar approval."
    });
  }

  if (method === "POST" && route === "/api/admin/login") {
    rateLimit(req, "admin-login", 8);
    const body = await readJson(req);
    const email = String(body.email ?? "").trim().toLowerCase();
    const password = String(body.password ?? "");
    const admin = db.prepare("SELECT id, email, salt, password_hash FROM admins WHERE email = ?").get(email);
    const candidate = admin ? passwordHash(password, admin.salt) : passwordHash(password, "invalid-account-salt");
    if (!admin || !safeEqual(candidate, admin.password_hash)) return json(res, 401, { error: "Email or password is incorrect." });
    const token = tokenFor({ sub: String(admin.id), email: admin.email, role: "admin" });
    recordAudit(admin.email, "admin.login", "session");
    setSessionCookie(res, token);
    return json(res, 200, { signedIn: true, email: admin.email });
  }

  if (method === "POST" && route === "/api/admin/logout") {
    const session = sessionFor(req);
    if (session) recordAudit(session.email, "admin.logout", "session");
    clearSessionCookie(res);
    return json(res, 200, { signedIn: false });
  }

  if (method === "GET" && route === "/api/admin/overview") {
    const admin = requireAdmin(req);
    const counts = db.prepare(`SELECT COUNT(*) AS registered,
      SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN otp_verified = 1 THEN 1 ELSE 0 END) AS otpVerified FROM voters`).get();
    return json(res, 200, { admin: { email: admin.email }, counts, crypto: cryptoReadiness });
  }

  if (method === "GET" && route === "/api/admin/voters") {
    requireAdmin(req);
    const voters = db.prepare(`SELECT id, full_name AS fullName, organization_id AS organizationId,
      email, status, otp_verified AS otpVerified, credential_issued AS credentialIssued, created_at AS createdAt
      FROM voters ORDER BY created_at DESC`).all();
    return json(res, 200, { voters });
  }

  if (method === "GET" && route === "/api/admin/elections") {
    requireAdmin(req);
    const ids = db.prepare("SELECT id FROM elections ORDER BY created_at DESC").all();
    return json(res, 200, { elections: ids.map((row) => getElection(row.id)).filter(Boolean) });
  }

  const voterDecisionMatch = route.match(/^\/api\/admin\/voters\/(\d+)\/(approve|reject)$/);
  if (method === "POST" && voterDecisionMatch) {
    const admin = requireAdmin(req);
    const voterId = Number(voterDecisionMatch[1]);
    const decision = voterDecisionMatch[2] === "approve" ? "approved" : "rejected";
    const voter = db.prepare("SELECT id, otp_verified FROM voters WHERE id = ?").get(voterId);
    if (!voter) return json(res, 404, { error: "Voter not found." });
    if (decision === "approved" && !voter.otp_verified) return json(res, 409, { error: "Verify the voter’s email or phone before approving eligibility." });
    transaction(() => {
      db.prepare("UPDATE voters SET status = ? WHERE id = ?").run(decision, voterId);
      recordAudit(admin.email, `voter.${decision}`, String(voterId));
    });
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
    const electionId = transaction(() => {
      const result = db.prepare(`INSERT INTO elections(title, description, starts_at, ends_at, status, created_at)
        VALUES (?, ?, ?, ?, 'draft', ?)`)
        .run(title, description, startsAt, endsAt, isoNow());
      const newId = Number(result.lastInsertRowid);
      const insertCandidate = db.prepare("INSERT INTO candidates(election_id, name, manifesto) VALUES (?, ?, ?)");
      for (const candidate of candidates) insertCandidate.run(newId, String(candidate.name).trim(), String(candidate.manifesto ?? "").trim());
      recordAudit(admin.email, "election.created", String(newId));
      return newId;
    });
    const election = getElection(electionId);
    return json(res, 201, { election });
  }

  const publishMatch = route.match(/^\/api\/admin\/elections\/(\d+)\/publish$/);
  if (method === "POST" && publishMatch) {
    const admin = requireAdmin(req);
    const id = Number(publishMatch[1]);
    const election = db.prepare("SELECT * FROM elections WHERE id = ?").get(id);
    if (!election) return json(res, 404, { error: "Election not found." });
    if (election.status !== "draft") return json(res, 409, { error: "Only draft elections can be published." });
    const complete = getElection(id);
    if (complete.candidates.length < 2) return json(res, 409, { error: "Add at least two candidates before publishing." });
    const now = Date.now();
    const status = new Date(complete.endsAt).getTime() <= now ? "closed" : new Date(complete.startsAt).getTime() <= now ? "active" : "scheduled";
    transaction(() => {
      db.prepare("UPDATE elections SET status = ?, manifest_hash = ? WHERE id = ?").run(status, complete.manifestHash, id);
      recordAudit(admin.email, "election.published", `${id}:${complete.manifestHash}`);
    });
    return json(res, 200, { election: getElection(id) });
  }

  if (method === "GET" && route === "/api/admin/audit-logs") {
    requireAdmin(req);
    return json(res, 200, { valid: verifyAuditChain(), logs: auditRows() });
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
server.listen(port, "127.0.0.1", () => {
  console.log(`Voting prototype available at http://localhost:${port}`);
  console.log(`Database: ${path.join(dataDir, "voting.sqlite")}`);
  console.log("Cryptographic voting submission is disabled until real verifiers are configured.");
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
