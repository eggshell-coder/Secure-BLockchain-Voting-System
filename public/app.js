const content = document.querySelector("#app-content");
const crumb = document.querySelector("#page-crumb");
const toast = document.querySelector("#toast");

const state = {
  view: "voter",
  elections: [],
  health: null,
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
    <div><strong>${escapeHtml(title)}</strong><p>This prototype has no reviewed anonymous credential, encryption, or proof-verification implementation connected. It will not accept or simulate a vote. No vote choice is collected.</p></div>
  </div>`;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers ?? {}) }
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error ?? `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return payload;
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
    </div>
    <h3>On the ballot</h3><div class="candidate-list">${candidates || `<div class="empty-state">No candidates have been added.</div>`}</div>
    <div class="manifest-row"><span>Frozen election manifest</span><code class="hash-code">${escapeHtml(election.manifestHash)}</code></div>
    <div class="locked-panel spaced-top"><strong>Voting is unavailable in this prototype</strong><p>The listed ballot is for interface review only. There is no vote button because the cryptographic ballot and verification layers are not implemented.</p></div>
  </article>`;
}

function renderVoter() {
  const cards = state.elections.length
    ? state.elections.map(renderElection).join("")
    : `<div class="card empty-state"><strong>No elections have been created</strong>Check back when an administrator publishes an election.</div>`;
  content.innerHTML = `<div class="hero-row"><div><span class="eyebrow">Your election workspace</span><h1>Make your voice count.</h1><p class="lead">Review election information and follow the registration process. This local prototype does not collect or submit ballots.</p></div><div class="hero-actions"><button class="button button-secondary" data-scroll="registration">Voter registration</button></div></div>
    ${banner()}
    <div class="grid-main"><section><div class="section-heading section-heading-first"><h2>Available elections</h2><p>${state.elections.length} listed</p></div><div class="right-stack">${cards}</div></section>
    <aside class="right-stack"><div class="card card-pad"><span class="eyebrow">How it works</span><h2 class="top-gap">Eligibility comes first.</h2><p class="card-subtitle">Registration records are separate from the ballot system. OTP confirms access to an email channel only; an organization registrar must still approve eligibility.</p><div class="steps"><div class="step"><span class="step-number">1</span><div><strong>Register your identity</strong><p>Provide your organization ID and contact email for registrar review.</p></div></div><div class="step"><span class="step-number">2</span><div><strong>Verify the demo code</strong><p>Local development shows the OTP on screen. It is not sent by email.</p></div></div><div class="step"><span class="step-number">3</span><div><strong>Wait for approval</strong><p>Even an approved registration cannot vote until reviewed cryptographic components are added.</p></div></div></div></div>
    <div class="plain-card"><span class="mini-label">Privacy boundary</span><p>Supabase Postgres stores identity information off-chain. Use fictional data while evaluating this prototype. Ballot choice data is never requested by this prototype.</p></div></aside></div>
    <section id="registration"><div class="section-heading"><h2>Voter registration</h2><p>Demo flow · no email provider connected</p></div><div class="card card-pad"><form id="register-form">
      <div class="form-grid"><div class="form-field"><label for="full-name">Full name</label><input class="input" id="full-name" name="fullName" autocomplete="name" required minlength="2" maxlength="120" /></div><div class="form-field"><label for="organization-id">Organization ID</label><input class="input" id="organization-id" name="organizationId" autocomplete="off" required minlength="3" maxlength="80" /></div><div class="form-field"><label for="email">Email address</label><input class="input" id="email" name="email" type="email" autocomplete="email" required maxlength="254" /></div></div>
      <div class="form-actions"><button class="button button-primary" type="submit">Request demo OTP</button><span class="form-note">The code is returned by the local API for demonstration.</span></div><div id="registration-message" aria-live="polite"></div>
    </form><form id="otp-form" class="hidden form-divider-top"><div class="form-grid"><div class="form-field"><label for="otp-organization-id">Organization ID</label><input class="input" id="otp-organization-id" name="organizationId" required autocomplete="off" /></div><div class="form-field"><label for="otp-code">Six digit demo code</label><input class="input" id="otp-code" name="otp" inputmode="numeric" pattern="[0-9]{6}" required maxlength="6" autocomplete="one-time-code" /></div></div><div class="form-actions"><button class="button button-secondary" type="submit">Verify code</button></div><div id="otp-message" aria-live="polite"></div></form></div></section>`;
}

function renderAdminLogin(error = "") {
  content.innerHTML = `<div class="hero-row"><div><span class="eyebrow">Restricted workspace</span><h1>Election administration.</h1><p class="lead">Manage registrar decisions, draft election manifests, and inspect the Postgres audit chain.</p></div></div>${banner("Administrator access does not enable voting")}
    <div class="card card-pad login-card"><span class="login-symbol" aria-hidden="true">▦</span><h2>Administrator sign in</h2><p class="card-subtitle">Use the administrator email and password configured in the server’s .env file. The sample configuration uses <strong>admin@demo.local</strong>.</p><form id="admin-login-form" class="form-top-gap"><div class="form-grid"><div class="form-field full"><label for="admin-email">Email</label><input class="input" id="admin-email" type="email" name="email" value="admin@demo.local" required autocomplete="username" /></div><div class="form-field full"><label for="admin-password">Password</label><input class="input" id="admin-password" type="password" name="password" required autocomplete="current-password" /></div></div><div class="form-actions"><button class="button button-primary" type="submit">Sign in</button></div>${error ? `<p class="inline-message error">${escapeHtml(error)}</p>` : ""}</form></div>`;
}

function renderVoterRows() {
  if (!state.voters.length) return `<div class="empty-state"><strong>No registrations yet</strong>New requests will appear here.</div>`;
  const rows = state.voters.map((voter) => `<tr><td><span class="table-primary">${escapeHtml(voter.fullName)}</span><br><span>${escapeHtml(voter.organizationId)}</span></td><td>${escapeHtml(voter.email)}</td><td><span class="tiny-state ${voter.status === "approved" ? "approved" : ""}">${escapeHtml(voter.status)}</span></td><td>${voter.otpVerified ? "Verified" : "Pending"}</td><td>${voter.status === "pending" ? `<button class="button button-small button-secondary" data-action="approve-voter" data-id="${escapeHtml(voter.id)}" ${voter.otpVerified ? "" : "disabled"}>Approve</button> <button class="button button-small button-danger" data-action="reject-voter" data-id="${escapeHtml(voter.id)}">Reject</button>` : "—"}</td></tr>`).join("");
  return `<div class="table-wrap"><table class="data-table"><thead><tr><th>Voter</th><th>Contact</th><th>Status</th><th>OTP</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderAdmin() {
  if (!state.admin) return renderAdminLogin();
  const counts = state.admin.counts ?? {};
  const elections = state.adminElections.map((election) => {
    const phase = electionPhase(election);
    return `<tr><td><span class="table-primary">${escapeHtml(election.title)}</span><br><span>#${escapeHtml(election.id)} · ${election.candidates.length} candidates</span></td><td><span class="tiny-state">${escapeHtml(phase)}</span></td><td><code class="hash-code">${escapeHtml(election.manifestHash.slice(0, 18))}…</code></td><td>${election.status === "draft" ? `<button class="button button-small button-primary" data-action="publish-election" data-id="${escapeHtml(election.id)}">Freeze & publish</button>` : "Manifest frozen"}</td></tr>`;
  }).join("");
  const auditStatus = state.audit ? (state.audit.valid ? "Chain integrity valid" : "Chain integrity failed") : "Not loaded";
  content.innerHTML = `<div class="hero-row"><div><span class="eyebrow">Administrator console</span><h1>Election operations.</h1><p class="lead">Signed in as ${escapeHtml(state.admin.email)}. Review registrations and freeze election manifests before publication.</p></div><div class="hero-actions"><button class="button button-quiet" data-action="admin-logout">Sign out</button></div></div>${banner("Election administration is available; ballot submission remains disabled")}
    <div class="stat-row"><div class="card stat-card"><span class="stat-label">Registrations</span><div class="stat-value">${Number(counts.registered ?? 0)}</div><div class="stat-foot">Identity records off-chain</div></div><div class="card stat-card"><span class="stat-label">Approved</span><div class="stat-value">${Number(counts.approved ?? 0)}</div><div class="stat-foot">Eligibility review complete</div></div><div class="card stat-card"><span class="stat-label">OTP verified</span><div class="stat-value">${Number(counts.otpVerified ?? 0)}</div><div class="stat-foot">Channel ownership only</div></div></div>
    <div class="admin-layout"><section><div class="card card-pad"><div class="card-head"><div><span class="eyebrow">Registrar queue</span><h2 class="heading-top-gap">Voter registrations</h2><p class="card-subtitle">Approval only records organization eligibility; this prototype does not issue anonymous credentials.</p></div><button class="button button-small button-secondary" data-action="refresh-admin">Refresh</button></div><div class="table-top-gap">${renderVoterRows()}</div></div>
    <div class="card card-pad card-top-gap"><div class="card-head"><div><span class="eyebrow">Election registry</span><h2 class="heading-top-gap">Election manifests</h2><p class="card-subtitle">Publishing freezes the candidate list and date configuration.</p></div></div><div class="table-wrap table-top-gap"><table class="data-table"><thead><tr><th>Election</th><th>Status</th><th>Manifest hash</th><th>Action</th></tr></thead><tbody>${elections || `<tr><td colspan="4" class="empty-state">No elections are available.</td></tr>`}</tbody></table></div></div></section>
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
    <section class="card card-pad verification-card"><span class="eyebrow">Cryptographic readiness</span><h2 class="top-gap">All voting components are unconfigured.</h2><p class="card-subtitle">A production deployment must publish verifiable evidence for each item below. This interface does not claim that a proof or tally has been verified.</p><div class="verification-steps">${requirements.map(([name, ready]) => `<div class="verification-step"><b><span class="tiny-state ${ready ? "approved" : ""}">${ready ? "Configured" : "Missing"}</span></b><span>${escapeHtml(name)}</span></div>`).join("")}</div></section>
    <div class="section-heading"><h2>Election manifests</h2><p>Hashes are local API records, not on-chain proofs.</p></div><div class="card card-pad"><div class="table-wrap"><table class="data-table"><thead><tr><th>Election</th><th>Manifest hash</th><th>Status</th><th>Browser check</th></tr></thead><tbody>${rows || `<tr><td colspan="4" class="empty-state">No elections to display.</td></tr>`}</tbody></table></div><p class="form-note verify-note-top-gap">“Matches” means this browser recomputed the hash from the API response. Independent verification still requires an on-chain contract address and source, ballot inclusion proofs, and a published tally proof. Those components are not part of this prototype.</p></div>`;
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
    await submitJson(form, "/api/auth/register", "Demo OTP created.", (result, values) => {
      const message = document.querySelector("#registration-message");
      message.innerHTML = `<p class="inline-message">${escapeHtml(result.message)} <strong>Demo OTP: ${escapeHtml(result.demoOtp)}</strong> · expires ${escapeHtml(formatDate(result.expiresAt))}</p>`;
      const otpForm = document.querySelector("#otp-form");
      otpForm.classList.remove("hidden");
      otpForm.elements.organizationId.value = values.organizationId;
      otpForm.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  }
  if (form.id === "otp-form") {
    await submitJson(form, "/api/auth/verify-otp", "Contact channel verified.", async () => {
      document.querySelector("#otp-message").innerHTML = `<p class="inline-message">Contact channel verified. Eligibility still requires registrar approval.</p>`;
    });
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

render();
