import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, publicKeyFromSecret } from "../lib/crypto/elgamal.ts";

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
    throw new Error("Usage: npm run election:keygen -- <draft-election-uuid>");
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

  const electionResponse = await fetch(`${baseUrl}/api/admin/elections`, {
    headers: { Accept: "application/json", Cookie: sessionCookie }
  });
  const elections = (await responseJson(electionResponse)).elections ?? [];
  const election = elections.find((item) => String(item.id).toLowerCase() === electionId.toLowerCase());
  if (!election) throw new Error("Election was not found or is not available to this admin account.");
  if (election.electionPublicKey || election.keyCeremonyStatus !== "not_started") {
    throw new Error("This election already has an assigned key; key generation is refused.");
  }
  if (election.status !== "draft") {
    throw new Error("Election keys can only be generated for a draft election.");
  }

  const dataDirectory = path.join(root, "data");
  const keyDirectory = path.resolve(root, process.env.ELECTION_KEY_DIR || "./data/election-keys");
  const relativeKeyDirectory = path.relative(dataDirectory, keyDirectory);
  if (!relativeKeyDirectory || relativeKeyDirectory === "." || relativeKeyDirectory.startsWith(`..${path.sep}`) || path.isAbsolute(relativeKeyDirectory)) {
    throw new Error("Election private-key files must stay inside the Git-ignored data/ directory.");
  }
  const keyPath = path.join(keyDirectory, `${electionId}.json`);
  mkdirSync(keyDirectory, { recursive: true, mode: 0o700 });

  let keyRecord;
  if (existsSync(keyPath)) {
    keyRecord = JSON.parse(readFileSync(keyPath, "utf8"));
    if (keyRecord.electionId !== electionId || keyRecord.scheme !== "ristretto255-exponential-elgamal-v1" ||
        typeof keyRecord.secretKey !== "string" || typeof keyRecord.publicKey !== "string" ||
        publicKeyFromSecret(keyRecord.secretKey) !== keyRecord.publicKey) {
      throw new Error(`Existing election key file is invalid or belongs to another election: ${keyPath}`);
    }
  } else {
    const pair = generateKeyPair();
    keyRecord = {
      scheme: "ristretto255-exponential-elgamal-v1",
      electionId,
      keyCeremonyStatus: "prototype_single_key",
      publicKey: pair.publicKey,
      secretKey: pair.secretKey,
      createdAt: new Date().toISOString()
    };
    // Create a new file only; never silently overwrite a private election key.
    writeFileSync(keyPath, `${JSON.stringify(keyRecord, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  }

  const keyResponse = await fetch(`${baseUrl}/api/admin/elections/${electionId}/prototype-key`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: origin,
      Cookie: sessionCookie
    },
    body: JSON.stringify({ publicKey: keyRecord.publicKey })
  });
  await responseJson(keyResponse);
  const fingerprint = createHash("sha256").update(Buffer.from(keyRecord.publicKey, "hex")).digest("hex");
  console.log(`Public key fingerprint (SHA-256): ${fingerprint}`);
}

main().catch(() => {
  console.error("Election key setup failed. Check the admin configuration and election status; no key material is printed.");
  process.exitCode = 1;
});
