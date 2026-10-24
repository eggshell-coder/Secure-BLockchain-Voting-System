import { createClient } from "@supabase/supabase-js";

const content = document.querySelector("#app-content");
const crumb = document.querySelector("#page-crumb");
const toast = document.querySelector("#toast");

const state = {
  view: "voter",
  elections: [],
  health: null,
  authConfig: null,
  authClient: null,
  authSession: null,
  authReady: false,
  authError: "",
  pendingEmail: "",
  voterRecord: null,
  admin: null,
  adminElections: [],
  voters: [],
  audit: null,
  toastTimer: null
};

const labels = { voter: "Voter portal", admin: "Election admin", verify: "Public verifier" };

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not set";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function electionPhase(election) {
  const now = Date.now();
  if (election.status === "draft") return "Draft";
  if (new Date(election.endsAt).getTime() <= now) return "Closed";
  if (new Date(election.startsAt).getTime() > now) return "Scheduled";
  return "Active";
}

function phaseClass(phase) {
  return phase.toLowerCase().replaceAll(" ", "-");
}

function banner(title = "Ballot submission is locked") {
  return `<div class="security-banner" role="status">
    <span class="security-icon" aria-hidden="true">!</span>
    <div><strong>${escapeHtml(title)}</strong><p>Local ballot encryption and validity proofs are available for development, but no reviewed eligibility proof or election acceptance flow is connected. This prototype will not accept or simulate a vote. No vote choice is collected.</p></div>
  </div>`;
}

async function api(path, options = {}) {
  const voterAuthRoute = path.startsWith("/api/auth/") || /\/semaphore-identity$/.test(path) || path === "/api/vote/relay";
  const authHeaders = voterAuthRoute && state.authSession?.access_token
    ? { Authorization: `Bearer ${state.authSession.access_token}` }
    : {};
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...authHeaders, ...(options.headers ?? {}) }
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error ?? `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function isAllowedStudentEmail(email) {
  const domain = String(email ?? "").trim().toLowerCase().split("@").at(-1);
  return Boolean(domain && state.authConfig?.allowedEmailDomains?.includes(domain));
}

async function loadVoterRecord() {
  if (!state.authSession) {
    state.voterRecord = null;
    return;
  }
  const email = state.authSession.user?.email;
  if (!isAllowedStudentEmail(email)) {
    state.voterRecord = null;
    return;
  }
  state.voterRecord = undefined;
  const result = await api("/api/auth/voter");
  state.voterRecord = result.voter ?? null;
}

async function initializeAuth() {
  try {
    const response = await fetch("/api/auth/config", { credentials: "same-origin" });
    if (!response.ok) throw new Error("Authentication configuration could not be loaded.");
    state.authConfig = await response.json();
    if (!state.authConfig.configured) {
      state.authReady = true;
      return;
    }
    state.authClient = createClient(state.authConfig.supabaseUrl, state.authConfig.publishableKey, {
      auth: { flowType: "pkce", autoRefreshToken: true, persistSession: true, detectSessionInUrl: true }
    });
    state.authClient.auth.onAuthStateChange((_event, session) => {
      state.authSession = session;
      state.authError = "";
      state.voterRecord = session ? undefined : null;
      window.setTimeout(() => {
        loadVoterRecord()
          .catch((error) => { state.authError = error.message; })
          .finally(() => render());
      }, 0);
    });
    const { data, error } = await state.authClient.auth.getSession();
    if (error) throw error;
    state.authSession = data.session;
    state.voterRecord = data.session ? undefined : null;
    if (data.session) await loadVoterRecord();
  } catch (error) {
    state.authError = error.message;
  } finally {
    state.authReady = true;
  }
}

function notify(message) {
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => toast.classList.remove("show"), 3200);
}

function renderNav() {
  document.querySelectorAll("[data-view]").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === state.view && item.classList.contains("nav-item"));
    if (item.classList.contains("nav-item")) item.setAttribute("aria-current", item.dataset.view === state.view ? "page" : "false");
  });
  crumb.textContent = labels[state.view];
}

async function refreshPublicData() {
  const [health, electionData] = await Promise.all([
    api("/api/health"),
    api("/api/elections")
  ]);
  state.health = health;
  state.elections = electionData.elections ?? [];
}

function renderElection(election) {
  const phase = electionPhase(election);
  const electionKeyReady = election.keyCeremonyStatus === "prototype_single_key" && Boolean(election.electionPublicKey);
  const credentialIssued = state.voterRecord?.semaphoreCredentialElectionIds?.includes(election.id) ?? false;
  const canEnrollIdentity = state.voterRecord?.status === "approved" && election.status === "scheduled" &&
    new Date(election.startsAt).getTime() > Date.now() && electionKeyReady;
  const candidates = election.candidates.map((candidate, index) => `<div class="candidate-card">
      <span class="candidate-avatar" aria-hidden="true">${index + 1}</span>
      <div class="candidate-body"><strong>${escapeHtml(candidate.name)}</strong><p>${escapeHtml(candidate.manifesto || "No statement provided.")}</p></div>
    </div>`).join("");
  return `<article class="card card-pad">
    <div class="card-head"><div><span class="eyebrow">Election #${escapeHtml(election.id)}</span><h2 class="election-title">${escapeHtml(election.title)}</h2><p class="election-description">${escapeHtml(election.description)}</p></div><span class="status-pill ${phaseClass(phase)}">${escapeHtml(phase)}</span></div>
    <div class="election-meta">
      <div class="meta-item"><span class="meta-label">Opens</span><span class="meta-value">${escapeHtml(formatDate(election.startsAt))}</span></div>
      <div class="meta-item"><span class="meta-label">Closes</span><span class="meta-value">${escapeHtml(formatDate(election.endsAt))}</span></div>
      <div class="meta-item"><span class="meta-label">Options</span><span class="meta-value">${election.candidates.length}</span></div>
      <div class="meta-item"><span class="meta-label">Encryption key</span><span class="meta-value">${electionKeyReady ? "Prototype single-admin key" : "Not configured"}</span></div>
    </div>
    <h3>On the ballot</h3><div class="candidate-list">${candidates || `<div class="empty-state">No candidates have been added.</div>`}</div>
    <div class="manifest-row"><span>Frozen election manifest</span><code class="hash-code">${escapeHtml(election.manifestHash)}</code></div>
    ${canEnrollIdentity ? `<div class="plain-card spaced-top"><span class="mini-label">Anonymous eligibility</span><p>Create an election-specific Semaphore identity. Its secret is encrypted on this device with a recovery passphrase; the server stores only its public commitment but can correlate it with your signed-in enrollment request.</p><button class="button button-secondary" data-action="create-semaphore-identity" data-id="${escapeHtml(election.id)}">Create anonymous identity</button></div>` : credentialIssued ? `<div class="plain-card spaced-top"><span class="mini-label">Anonymous eligibility</span><p>An identity was registered for this election. Restore the encrypted identity vault on this device if needed; the server cannot recover the secret.</p></div>` : ""}
    <div class="locked-panel spaced-top"><strong>Voting is unavailable in this prototype</strong><p>${electionKeyReady ? "A prototype election public key is published. Browser encryption, ballot and eligibility proof checks, database acceptance, and an attested contract relay now have prototype implementations." : "Encryption is unavailable because this election has no configured public key."} The full Supabase and chain flow has not been deployed and independently reviewed, so ballot submission stays locked.</p></div>
  </article>`;
}

function renderVoterAuth() {
  if (!state.authReady) return `<div class="card card-pad"><p class="card-subtitle">Loading university sign-in…</p></div>`;
  if (!state.authConfig?.configured) {
    return `<div class="card card-pad"><h3>University sign-in is not configured</h3><p class="card-subtitle">Set the Supabase publishable key and approved student email domains in the server environment. Then enable Google Auth and custom SMTP in Supabase.</p></div>`;
  }
  if (!state.authSession) {
    return `<div class="card card-pad">
      <span class="eyebrow">Verified university account required</span><h3 class="heading-top-gap">Sign in to register</h3>
      <p class="card-subtitle">Use your university Google account or request a real email code. Your email is verified by Supabase Auth; the registrar still checks your student ID.</p>
      ${state.authError ? `<p class="inline-message error" role="alert">${escapeHtml(state.authError)}</p>` : ""}
      <div class="form-actions"><button class="button button-primary" type="button" data-action="google-sign-in">Continue with Google</button></div>
      <form id="email-otp-send-form" class="form-top-gap"><div class="form-field"><label for="auth-email">University email</label><input class="input" id="auth-email" name="email" type="email" autocomplete="email" required maxlength="254" /></div><div class="form-actions"><button class="button button-secondary" type="submit">Send sign-in code</button></div><div class="form-note">The code is sent by Supabase Auth using the configured email provider.</div><div id="auth-email-message" aria-live="polite"></div></form>
      <form id="email-otp-verify-form" class="hidden form-divider-top"><div class="form-grid"><div class="form-field"><label for="auth-verify-email">University email</label><input class="input" id="auth-verify-email" name="email" type="email" autocomplete="email" required maxlength="254" /></div><div class="form-field"><label for="auth-email-code">Email code</label><input class="input" id="auth-email-code" name="token" inputmode="numeric" pattern="[0-9]{6}" required maxlength="6" autocomplete="one-time-code" /></div></div><div class="form-actions"><button class="button button-secondary" type="submit">Verify code</button></div><div id="auth-verify-message" aria-live="polite"></div></form>
    </div>`;
  }

  const email = state.authSession.user?.email ?? "";
  if (!isAllowedStudentEmail(email)) {
    return `<div class="card card-pad"><h3>Use your university student account</h3><p class="card-subtitle">The signed-in account does not match an approved student email domain.</p><p class="form-note">Signed in as ${escapeHtml(email)}</p><button class="button button-secondary" type="button" data-action="voter-sign-out">Sign out</button></div>`;
  }
  if (state.voterRecord === undefined) return `<div class="card card-pad"><p class="card-subtitle">Checking your registration…</p></div>`;
  if (state.voterRecord) {
    const status = state.voterRecord.status;
    const detail = status === "approved"
      ? "Your student eligibility has been approved. Create an election-specific encrypted anonymous identity before the group freezes. Ballot submission remains disabled pending independent review."
      : status === "rejected"
        ? "The registrar rejected this registration. Contact the election administrator if you think this decision is incorrect."
        : "Your verified account is registered. An election administrator must check your student ID and approve eligibility.";
    return `<div class="card card-pad"><div class="card-head"><div><span class="eyebrow">University account</span><h3 class="heading-top-gap">Registration ${escapeHtml(status)}</h3></div><button class="button button-small button-secondary" type="button" data-action="voter-sign-out">Sign out</button></div><p class="card-subtitle">${escapeHtml(detail)}</p><div class="form-note">${escapeHtml(state.voterRecord.fullName)} · ${escapeHtml(state.voterRecord.organizationId)} · ${escapeHtml(email)}</div></div>`;
  }

  return `<div class="card card-pad"><div class="card-head"><div><span class="eyebrow">Verified university account</span><h3 class="heading-top-gap">Complete voter registration</h3></div><button class="button button-small button-secondary" type="button" data-action="voter-sign-out">Sign out</button></div><p class="card-subtitle">Signed in as ${escapeHtml(email)}. Enter your name and student ID; an election administrator will check your eligibility.</p>${state.authError ? `<p class="inline-message error" role="alert">${escapeHtml(state.authError)}</p>` : ""}<form id="register-form" class="form-top-gap"><div class="form-grid"><div class="form-field"><label for="full-name">Full name</label><input class="input" id="full-name" name="fullName" autocomplete="name" required minlength="2" maxlength="120" /></div><div class="form-field"><label for="organization-id">University student ID</label><input class="input" id="organization-id" name="organizationId" autocomplete="off" required minlength="3" maxlength="80" /></div></div><div class="form-actions"><button class="button button-primary" type="submit">Submit for registrar review</button></div><div id="registration-message" aria-live="polite"></div></form></div>`;
}

function renderVoter() {
  const cards = state.elections.length
    ? state.elections.map(renderElection).join("")
    : `<div class="card empty-state"><strong>No elections have been created</strong>Check back when an administrator publishes an election.</div>`;
  content.innerHTML = `<div class="hero-row"><div><span class="eyebrow">Your election workspace</span><h1>Make your voice count.</h1><p class="lead">Sign in with your verified student account, complete registrar review, and enroll your anonymous eligibility identity before the election begins. Prototype ballot casting remains locked until independent review and deployment checks are complete.</p></div><div class="hero-actions"><button class="button button-secondary" data-scroll="registration">Voter registration</button></div></div>
    ${banner()}
    <div class="grid-main"><section><div class="section-heading section-heading-first"><h2>Available elections</h2><p>${state.elections.length} listed</p></div><div class="right-stack">${cards}</div></section>
    <aside class="right-stack"><div class="card card-pad"><span class="eyebrow">How eligibility works</span><h2 class="top-gap">Same university, verified individually.</h2><p class="card-subtitle">Google or email sign-in verifies control of a university account. It does not prove current enrollment; an election registrar checks the student ID and approves the registration.</p><div class="steps"><div class="step"><span class="step-number">1</span><div><strong>Sign in with university email</strong><p>Supabase Auth verifies Google sign-in or an email code.</p></div></div><div class="step"><span class="step-number">2</span><div><strong>Submit student ID</strong><p>The registrar checks it against the organization’s student roster.</p></div></div><div class="step"><span class="step-number">3</span><div><strong>Enroll an anonymous identity</strong><p>The browser keeps the identity secret encrypted. The issuer can still correlate the enrollment request and commitment.</p></div></div></div></div>
    <div class="plain-card"><span class="mini-label">Privacy boundary</span><p>Supabase stores verified identity and eligibility off-chain. The current UI does not collect candidate choices; encrypted ballot submission remains disabled until the prototype passes independent review and deployment checks.</p></div></aside></div>
    <section id="registration"><div class="section-heading"><h2>Voter registration</h2><p>University account required · registrar approval</p></div>${renderVoterAuth()}</section>`;
}

function renderAdminLogin(error = "") {
  content.innerHTML = `<div class="hero-row"><div><span class="eyebrow">Restricted workspace</span><h1>Election administration.</h1><p class="lead">Manage registrar decisions, draft election manifests, and inspect the Postgres audit chain.</p></div></div>${banner("Administrator access does not enable voting")}
    <div class="card card-pad login-card"><span class="login-symbol" aria-hidden="true">▦</span><h2>Administrator sign in</h2><p class="card-subtitle">Use the administrator email and password configured in the server’s .env file. The sample configuration uses <strong>admin@demo.local</strong>.</p><form id="admin-login-form" class="form-top-gap"><div class="form-grid"><div class="form-field full"><label for="admin-email">Email</label><input class="input" id="admin-email" type="email" name="email" value="admin@demo.local" required autocomplete="username" /></div><div class="form-field full"><label for="admin-password">Password</label><input class="input" id="admin-password" type="password" name="password" required autocomplete="current-password" /></div></div><div class="form-actions"><button class="button button-primary" type="submit">Sign in</button></div>${error ? `<p class="inline-message error">${escapeHtml(error)}</p>` : ""}</form></div>`;
}

function renderVoterRows() {
  if (!state.voters.length) return `<div class="empty-state"><strong>No registrations yet</strong>New requests will appear here.</div>`;
  const rows = state.voters.map((voter) => `<tr><td><span class="table-primary">${escapeHtml(voter.fullName)}</span><br><span>${escapeHtml(voter.organizationId)}</span></td><td>${escapeHtml(voter.email)}</td><td><span class="tiny-state ${voter.status === "approved" ? "approved" : ""}">${escapeHtml(voter.status)}</span></td><td>${voter.emailVerified ? "Verified" : "Pending"}</td><td>${voter.status === "pending" ? `<button class="button button-small button-secondary" data-action="approve-voter" data-id="${escapeHtml(voter.id)}" ${voter.emailVerified ? "" : "disabled"}>Approve</button> <button class="button button-small button-danger" data-action="reject-voter" data-id="${escapeHtml(voter.id)}">Reject</button>` : "—"}</td></tr>`).join("");
  return `<div class="table-wrap"><table class="data-table"><thead><tr><th>Voter</th><th>Contact</th><th>Status</th><th>Email</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderAdmin() {
  if (!state.admin) return renderAdminLogin();
  const counts = state.admin.counts ?? {};
  const elections = state.adminElections.map((election) => {
    const phase = electionPhase(election);
    const keyReady = election.keyCeremonyStatus === "prototype_single_key" && Boolean(election.electionPublicKey);
    const keyStatus = keyReady ? "Prototype single-admin key" : "Key required";
    const groupStatus = election.semaphoreGroupFrozenAt ? "Frozen" : "Enrollment open";
    const action = election.status === "scheduled" && !election.semaphoreGroupFrozenAt
      ? `<button class="button button-small button-secondary" data-action="freeze-semaphore-group" data-id="${escapeHtml(election.id)}">Freeze voter group</button>`
      : election.status !== "draft" ? "Manifest frozen" : keyReady
      ? `<button class="button button-small button-primary" data-action="publish-election" data-id="${escapeHtml(election.id)}">Freeze & publish</button>`
      : `<button class="button button-small button-secondary" disabled title="Run the election key setup command first.">Key required</button>`;
    return `<tr><td><span class="table-primary">${escapeHtml(election.title)}</span><br><span>#${escapeHtml(election.id)} · ${election.candidates.length} candidates</span></td><td><span class="tiny-state">${escapeHtml(phase)}</span></td><td>${escapeHtml(keyStatus)}</td><td>${escapeHtml(groupStatus)}</td><td><code class="hash-code">${escapeHtml(election.manifestHash.slice(0, 18))}…</code></td><td>${action}</td></tr>`;
  }).join("");
  const auditStatus = state.audit ? (state.audit.valid ? "Chain integrity valid" : "Chain integrity failed") : "Not loaded";
  content.innerHTML = `<div class="hero-row"><div><span class="eyebrow">Administrator console</span><h1>Election operations.</h1><p class="lead">Signed in as ${escapeHtml(state.admin.email)}. Review registrations and freeze election manifests before publication.</p></div><div class="hero-actions"><button class="button button-quiet" data-action="admin-logout">Sign out</button></div></div>${banner("Election administration is available; ballot submission remains disabled")}
    <div class="stat-row"><div class="card stat-card"><span class="stat-label">Registrations</span><div class="stat-value">${Number(counts.registered ?? 0)}</div><div class="stat-foot">Identity records off-chain</div></div><div class="card stat-card"><span class="stat-label">Approved</span><div class="stat-value">${Number(counts.approved ?? 0)}</div><div class="stat-foot">Eligibility review complete</div></div><div class="card stat-card"><span class="stat-label">Email verified</span><div class="stat-value">${Number(counts.emailVerified ?? 0)}</div><div class="stat-foot">Channel ownership only</div></div></div>
    <div class="admin-layout"><section><div class="card card-pad"><div class="card-head"><div><span class="eyebrow">Registrar queue</span><h2 class="heading-top-gap">Voter registrations</h2><p class="card-subtitle">Approval records organization eligibility. Approved voters enroll an election-specific anonymous identity separately.</p></div><button class="button button-small button-secondary" data-action="refresh-admin">Refresh</button></div><div class="table-top-gap">${renderVoterRows()}</div></div>
    <div class="card card-pad card-top-gap"><div class="card-head"><div><span class="eyebrow">Election registry</span><h2 class="heading-top-gap">Election manifests</h2><p class="card-subtitle">Generate the prototype single-admin key before publishing. Enroll approved voters, then freeze the group before voting starts. The private election key stays in <code>data/election-keys/</code>; protect and back it up securely.</p></div></div><div class="table-wrap table-top-gap"><table class="data-table"><thead><tr><th>Election</th><th>Status</th><th>Key status</th><th>Semaphore group</th><th>Manifest hash</th><th>Action</th></tr></thead><tbody>${elections || `<tr><td colspan="6" class="empty-state">No elections are available.</td></tr>`}</tbody></table></div></div></section>
    <aside class="right-stack"><div class="card card-pad"><span class="eyebrow">Create election</span><h2 class="heading-top-gap">Draft a ballot manifest</h2><p class="card-subtitle">Use one candidate per line: <code>Name | manifesto</code>. At least two candidates are required.</p><form id="election-form" class="form-top-gap"><div class="form-grid"><div class="form-field full"><label for="election-title">Election title</label><input class="input" id="election-title" name="title" required minlength="4" maxlength="160" /></div><div class="form-field full"><label for="election-description">Description</label><textarea class="textarea" id="election-description" name="description" maxlength="1000"></textarea></div><div class="form-field"><label for="starts-at">Opens</label><input class="input" id="starts-at" name="startsAt" type="datetime-local" required /></div><div class="form-field"><label for="ends-at">Closes</label><input class="input" id="ends-at" name="endsAt" type="datetime-local" required /></div><div class="form-field full"><label for="candidate-lines">Candidates</label><textarea class="textarea" id="candidate-lines" name="candidates" placeholder="Candidate A | Short platform statement&#10;Candidate B | Short platform statement" required></textarea></div></div><div class="form-actions"><button class="button button-primary" type="submit">Save draft</button></div><div id="election-message" aria-live="polite"></div></form></div>
    <div class="card card-pad"><span class="eyebrow">Audit trail</span><h2 class="heading-top-gap">${escapeHtml(auditStatus)}</h2><p class="card-subtitle">Postgres serializes audit events into an append-only hash chain. Independent checkpoints and external review are still needed for a production election.</p><button class="button button-small button-secondary table-top-gap" data-action="refresh-audit">Inspect latest entries</button><div class="audit-top-gap" id="audit-entries">${state.audit ? renderAuditEntries() : ""}</div></div></aside></div>`;
}

function renderAuditEntries() {
  if (!state.audit?.logs?.length) return `<p class="form-note">No audit entries yet.</p>`;
  return `<div class="table-wrap"><table class="data-table"><thead><tr><th>Event</th><th>Subject</th><th>Time</th></tr></thead><tbody>${state.audit.logs.slice(0, 8).map((row) => `<tr><td>${escapeHtml(row.action)}<br><span>${escapeHtml(row.actor)}</span></td><td>${escapeHtml(row.subject)}</td><td>${escapeHtml(formatDate(row.createdAt))}</td></tr>`).join("")}</tbody></table></div>`;
}

async function manifestDigest(election) {
  if (!globalThis.crypto?.subtle) return null;
  const canonical = JSON.stringify({
    electionId: String(election.id),
    title: election.title,
    description: election.description,
    startsAt: election.startsAt,
    endsAt: election.endsAt,
    ...(election.electionPublicKey ? { electionPublicKey: election.electionPublicKey } : {}),
    candidates: election.candidates.map((candidate, index) => ({
      position: index + 1,
      name: candidate.name,
      manifesto: candidate.manifesto
    }))
  });
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function renderVerify() {
  const crypto = state.health?.crypto ?? {};
  const requirements = [
    ["Anonymous credential issuer", crypto.anonymousCredentialIssuer],
    ["Eligibility proof verifier", crypto.eligibilityProofVerifier],
    ["Encrypted ballot client", crypto.encryptedBallot],
    ["Ballot validity proof", crypto.ballotValidityProof],
    ["Tally proof verifier", crypto.tallyProofVerifier]
  ];
  const rows = (await Promise.all(state.elections.map(async (election) => {
    let digest = null;
    try { digest = await manifestDigest(election); } catch { digest = null; }
    const result = digest === null ? "Unavailable" : digest === election.manifestHash ? "Matches" : "Mismatch";
    const resultClass = result === "Matches" ? "approved" : result === "Mismatch" ? "failed" : "";
    return `<tr><td><span class="table-primary">${escapeHtml(election.title)}</span><br><span>Election #${escapeHtml(election.id)}</span></td><td><code class="hash-code">${escapeHtml(election.manifestHash)}</code></td><td>${escapeHtml(electionPhase(election))}</td><td><span class="tiny-state ${resultClass}">${result}</span></td></tr>`;
  }))).join("");
  content.innerHTML = `<div class="hero-row"><div><span class="eyebrow">Public verification</span><h1>Verify the published record.</h1><p class="lead">Review election configuration and the system’s declared cryptographic readiness.</p></div></div>${banner("There is no deployed chain to verify in this local prototype")}
    <section class="card card-pad verification-card"><span class="eyebrow">Cryptographic readiness</span><h2 class="top-gap">Production gates remain closed.</h2><p class="card-subtitle">Several prototype components are implemented, but none is marked ready until deployed configuration and independent review evidence are available. This interface does not claim a live proof or tally has been verified.</p><div class="verification-steps">${requirements.map(([name, ready]) => `<div class="verification-step"><b><span class="tiny-state ${ready ? "approved" : ""}">${ready ? "Cleared" : "Review required"}</span></b><span>${escapeHtml(name)}</span></div>`).join("")}</div></section>
    <div class="section-heading"><h2>Election manifests</h2><p>Hashes are API records; published ballots can be exported for independent checking.</p></div><div class="card card-pad"><div class="table-wrap"><table class="data-table"><thead><tr><th>Election</th><th>Manifest hash</th><th>Status</th><th>Browser check</th></tr></thead><tbody>${rows || `<tr><td colspan="4" class="empty-state">No elections to display.</td></tr>`}</tbody></table></div><p class="form-note verify-note-top-gap">“Matches” means this browser recomputed the hash from the API response. The public verifier checks exported ballot and tally data. The chain attestor and tally settlement still need independent review and deployment.</p></div>`;
}

async function loadAdmin() {
  const overview = await api("/api/admin/overview");
  state.admin = { ...overview.admin, counts: overview.counts };
  const [voters, elections, audit] = await Promise.all([
    api("/api/admin/voters"),
    api("/api/admin/elections"),
    api("/api/admin/audit-logs")
  ]);
  state.voters = voters.voters ?? [];
  state.adminElections = elections.elections ?? [];
  state.audit = audit;
}

async function render() {
  renderNav();
  content.innerHTML = `<div class="loading"><span class="spinner"></span><span>Loading election workspace…</span></div>`;
  try {
    await refreshPublicData();
    if (state.view === "voter") renderVoter();
    if (state.view === "verify") await renderVerify();
    if (state.view === "admin") {
      try {
        await loadAdmin();
      } catch (error) {
        if (error.status === 401) {
          state.admin = null;
          renderAdminLogin();
        } else throw error;
      }
      if (state.admin) renderAdmin();
    }
  } catch (error) {
    content.innerHTML = `<div class="card card-pad"><h2>Workspace unavailable</h2><p class="card-subtitle">${escapeHtml(error.message)}</p><button class="button button-secondary retry-top-gap" data-action="retry">Try again</button></div>`;
  }
}

async function submitJson(form, endpoint, successMessage, onSuccess) {
  const button = form.querySelector("button[type=submit]");
  if (button) button.disabled = true;
  try {
    const values = Object.fromEntries(new FormData(form).entries());
    const result = await api(endpoint, { method: "POST", body: JSON.stringify(values) });
    if (onSuccess) await onSuccess(result, values);
    if (successMessage) notify(successMessage);
  } catch (error) {
    const message = form.querySelector("[aria-live]");
    if (message) message.innerHTML = `<p class="inline-message error">${escapeHtml(error.message)}</p>`;
    else notify(error.message);
  } finally {
    if (button?.isConnected) button.disabled = false;
  }
}

document.addEventListener("click", async (event) => {
  const nav = event.target.closest("[data-view]");
  if (nav) {
    event.preventDefault();
    state.view = nav.dataset.view;
    await render();
    return;
  }
  const scroll = event.target.closest("[data-scroll]");
  if (scroll) {
    document.getElementById(scroll.dataset.scroll)?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const action = event.target.closest("[data-action]");
  if (!action) return;
  try {
    action.disabled = true;
    if (action.dataset.action === "retry") return render();
    if (action.dataset.action === "create-semaphore-identity") {
      const election = state.elections.find((item) => item.id === action.dataset.id);
      if (!election || state.voterRecord?.status !== "approved" || !state.authSession?.access_token) {
        throw new Error("Sign in with an approved voter registration before creating an identity.");
      }
      if (!globalThis.votingSemaphore) throw new Error("The Semaphore client bundle has not loaded.");
      let vault = globalThis.votingSemaphore.loadSemaphoreIdentityVault(election.id);
      if (!vault) {
        const passphrase = window.prompt("Create a recovery passphrase (at least 12 characters). It encrypts your anonymous identity on this device.");
        if (!passphrase) return;
        const confirmation = window.prompt("Enter the recovery passphrase again.");
        if (confirmation !== passphrase) throw new Error("The recovery passphrases do not match.");
        const created = await globalThis.votingSemaphore.createEncryptedSemaphoreIdentity(election.id, passphrase);
        vault = created.vault;
        globalThis.votingSemaphore.saveSemaphoreIdentityVault(vault);
      }
      await api(`/api/elections/${encodeURIComponent(election.id)}/semaphore-identity`, {
        method: "POST",
        body: JSON.stringify({ commitment: vault.commitment })
      });
      await loadVoterRecord();
      renderVoter();
      notify("Your encrypted anonymous identity was registered. Keep the recovery passphrase safe.");
      return;
    }
    if (action.dataset.action === "google-sign-in") {
      if (!state.authClient) throw new Error("University sign-in is not configured.");
      const { error } = await state.authClient.auth.signInWithOAuth({
        provider: "google",
        options: { redirectTo: window.location.origin }
      });
      if (error) throw error;
      return;
    }
    if (action.dataset.action === "voter-sign-out") {
      if (!state.authClient) throw new Error("University sign-in is not configured.");
      const { error } = await state.authClient.auth.signOut();
      if (error) throw error;
      state.authSession = null;
      state.voterRecord = null;
      await render();
      notify("You have signed out.");
      return;
    }
    if (action.dataset.action === "refresh-admin") {
      await loadAdmin();
      renderAdmin();
    }
    if (action.dataset.action === "refresh-audit") {
      state.audit = await api("/api/admin/audit-logs");
      renderAdmin();
      document.querySelector("#audit-entries")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
    if (action.dataset.action === "admin-logout") {
      await api("/api/admin/logout", { method: "POST", body: "{}" });
      state.admin = null;
      renderAdminLogin();
      notify("You have signed out.");
    }
    if (action.dataset.action === "approve-voter" || action.dataset.action === "reject-voter") {
      const decision = action.dataset.action === "approve-voter" ? "approve" : "reject";
      await api(`/api/admin/voters/${encodeURIComponent(action.dataset.id)}/${decision}`, { method: "POST", body: "{}" });
      await loadAdmin();
      renderAdmin();
      notify(`Voter ${decision === "approve" ? "approved" : "rejected"}.`);
    }
    if (action.dataset.action === "publish-election") {
      await api(`/api/admin/elections/${encodeURIComponent(action.dataset.id)}/publish`, { method: "POST", body: "{}" });
      await refreshPublicData();
      await loadAdmin();
      renderAdmin();
      notify("Election manifest frozen and published.");
    }
    if (action.dataset.action === "freeze-semaphore-group") {
      await api(`/api/admin/elections/${encodeURIComponent(action.dataset.id)}/freeze-semaphore-group`, { method: "POST", body: "{}" });
      await refreshPublicData();
      await loadAdmin();
      renderAdmin();
      notify("Semaphore voter group frozen. New identities can no longer join.");
    }
  } catch (error) {
    notify(error.message);
    if (error.status === 401 && state.view === "admin") {
      state.admin = null;
      renderAdminLogin();
      return;
    }
    action.disabled = false;
  }
});

document.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  if (form.id === "register-form") {
    await submitJson(form, "/api/auth/register", "Registration sent for review.", async () => {
      await loadVoterRecord();
      renderVoter();
    });
  }
  if (form.id === "email-otp-send-form") {
    const message = form.querySelector("[aria-live]");
    const button = form.querySelector("button[type=submit]");
    const email = String(new FormData(form).get("email") ?? "").trim().toLowerCase();
    button.disabled = true;
    try {
      if (!state.authClient) throw new Error("University sign-in is not configured.");
      if (!isAllowedStudentEmail(email)) throw new Error("Enter an approved student email address.");
      const { error } = await state.authClient.auth.signInWithOtp({
        email,
        options: { shouldCreateUser: true, emailRedirectTo: window.location.origin }
      });
      if (error) throw error;
      state.pendingEmail = email;
      const verifyForm = document.querySelector("#email-otp-verify-form");
      verifyForm.classList.remove("hidden");
      verifyForm.elements.email.value = email;
      message.innerHTML = `<p class="inline-message">A sign-in code was sent to ${escapeHtml(email)}. Check your inbox.</p>`;
      verifyForm.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (error) {
      message.innerHTML = `<p class="inline-message error" role="alert">${escapeHtml(error.message)}</p>`;
    } finally {
      if (button?.isConnected) button.disabled = false;
    }
  }
  if (form.id === "email-otp-verify-form") {
    const message = form.querySelector("[aria-live]");
    const button = form.querySelector("button[type=submit]");
    const values = Object.fromEntries(new FormData(form).entries());
    const email = String(values.email ?? "").trim().toLowerCase();
    const token = String(values.token ?? "").trim();
    button.disabled = true;
    try {
      if (!state.authClient) throw new Error("University sign-in is not configured.");
      if (email !== state.pendingEmail || !/^\d{6}$/.test(token)) throw new Error("Enter the six-digit code sent to the same email address.");
      const { data, error } = await state.authClient.auth.verifyOtp({ email, token, type: "email" });
      if (error) throw error;
      state.authSession = data.session;
      state.authError = "";
      await loadVoterRecord();
      renderVoter();
      notify("University email verified.");
    } catch (error) {
      message.innerHTML = `<p class="inline-message error" role="alert">${escapeHtml(error.message)}</p>`;
    } finally {
      if (button?.isConnected) button.disabled = false;
    }
  }
  if (form.id === "admin-login-form") {
    await submitJson(form, "/api/admin/login", "Administrator signed in.", async () => {
      state.admin = null;
      await loadAdmin();
      renderAdmin();
    });
  }
  if (form.id === "election-form") {
    const lines = String(new FormData(form).get("candidates") ?? "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const candidates = lines.map((line) => {
      const [name, ...manifestoParts] = line.split("|");
      return { name: name.trim(), manifesto: manifestoParts.join("|").trim() };
    });
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const startsAt = new Date(form.elements.startsAt.value);
      const endsAt = new Date(form.elements.endsAt.value);
      if (!Number.isFinite(startsAt.getTime()) || !Number.isFinite(endsAt.getTime())) throw new Error("Choose valid start and end dates.");
      const body = {
        title: form.elements.title.value,
        description: form.elements.description.value,
        startsAt: startsAt.toISOString(),
        endsAt: endsAt.toISOString(),
        candidates
      };
      await api("/api/admin/elections", { method: "POST", body: JSON.stringify(body) });
      await refreshPublicData();
      await loadAdmin();
      renderAdmin();
      notify("Election draft saved.");
    } catch (error) {
      document.querySelector("#election-message").innerHTML = `<p class="inline-message error">${escapeHtml(error.message)}</p>`;
      button.disabled = false;
    }
  }
});

document.querySelector("#account-button").addEventListener("click", () => {
  state.view = "admin";
  render();
});

initializeAuth().finally(() => render());
