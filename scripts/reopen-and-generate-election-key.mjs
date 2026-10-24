import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function loadDotEnv() {
  const envPath = path.join(root, ".env");
  if (!existsSync(envPath)) return;
  for (const line of readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const match = line.trim().match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    process.env[match[1]] = value;
  }
}

function readElectionId() {
  const id = process.argv[2];
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id ?? "")) {
    throw new Error("Usage: npm run election:reopen-keygen -- <election-uuid>");
  }
  return id;
}

async function responseJson(response) {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error ?? `The election server returned HTTP ${response.status}.`);
  return body;
}

async function main() {
  loadDotEnv();
  const electionId = readElectionId();
  const baseUrl = (process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || "4173"}`).replace(/\/+$/, "");
  const origin = new URL(baseUrl).origin;
  const adminEmail = (process.env.ADMIN_EMAIL ?? "").trim();
  const adminPassword = process.env.ADMIN_PASSWORD ?? "";
  if (!adminEmail || !adminPassword || /replace-with|change-me-now/i.test(adminPassword)) {
    throw new Error("Set the real local ADMIN_EMAIL and ADMIN_PASSWORD before running election key setup.");
  }

  const loginResponse = await fetch(`${baseUrl}/api/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify({ email: adminEmail, password: adminPassword })
  });
  await responseJson(loginResponse);
  const setCookies = loginResponse.headers.getSetCookie?.() ?? [loginResponse.headers.get("set-cookie") ?? ""];
  const sessionCookie = setCookies.map((cookie) => cookie.split(";", 1)[0]).find((cookie) => cookie.startsWith("session="));
  if (!sessionCookie) throw new Error("The server did not issue an admin session cookie.");

  await responseJson(await fetch(`${baseUrl}/api/admin/elections/${electionId}/reopen-for-key-setup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: origin,
      Cookie: sessionCookie
    },
    body: "{}"
  }));

  const child = spawnSync(process.execPath, [
    "--experimental-strip-types",
    path.join(root, "scripts", "generate-election-key.mjs"),
    electionId
  ], { cwd: root, env: process.env, stdio: "inherit" });
  if (child.error) throw new Error("The election key generator could not be started.");
  if (child.status !== 0) process.exitCode = child.status ?? 1;
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "";
  const safeMessages = new Set([
    "Set the real local ADMIN_EMAIL and ADMIN_PASSWORD before running election key setup.",
    "The server did not issue an admin session cookie.",
    "Election not found.",
    "An election key is already configured; reopening is refused.",
    "A frozen Semaphore group exists; reopening is refused.",
    "This election has started; reopening is refused.",
    "Ballots, voter enrollments, a contract deployment, or a tally exist; reopening is refused.",
    "Only a scheduled election with a cleared manifest can be reopened for key setup.",
    "This election cannot be reopened for key setup."
  ]);
  console.error(safeMessages.has(message)
    ? `Election key recovery refused: ${message} No key material was printed.`
    : "Election key recovery failed. Check the admin configuration and server; no key material was printed.");
  process.exitCode = 1;
});
