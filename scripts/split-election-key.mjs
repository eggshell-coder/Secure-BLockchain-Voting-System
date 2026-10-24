import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createShamirTrusteeShares } from "../lib/crypto/tally.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const electionId = process.argv[2] ?? "";
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(electionId)) {
  throw new Error("Usage: npm run election:split-key -- <election-uuid>");
}

const dataDirectory = path.resolve(root, process.env.ELECTION_KEY_DIR || "./data/election-keys");
const masterPath = path.join(dataDirectory, `${electionId}.json`);
if (!existsSync(masterPath)) throw new Error(`Election key file was not found: ${masterPath}`);
const master = JSON.parse(readFileSync(masterPath, "utf8"));
if (master.electionId !== electionId || master.keyCeremonyStatus !== "prototype_single_key") {
  throw new Error("The source election key is not a prototype single-admin key for this election.");
}

const destination = path.join(dataDirectory, `${electionId}-trustees-2-of-3`);
if (existsSync(destination)) throw new Error(`Trustee share directory already exists: ${destination}`);
const temporaryDirectory = `${destination}.tmp-${randomBytes(6).toString("hex")}`;
mkdirSync(temporaryDirectory, { recursive: true, mode: 0o700 });
try {
  const split = createShamirTrusteeShares(master.secretKey, 2, 3);
  if (split.electionPublicKey !== master.publicKey) throw new Error("Generated shares do not reconstruct the configured election key.");
  for (const share of split.shares) {
    const record = {
      version: 1,
      scheme: "ristretto255-exponential-elgamal-v1/shamir-2-of-3",
      electionId,
      electionPublicKey: split.electionPublicKey,
      threshold: 2,
      totalTrustees: 3,
      index: share.index,
      publicShare: share.publicShare,
      secretShare: share.secretShare
    };
    writeFileSync(path.join(temporaryDirectory, `trustee-${share.index}.json`),
      `${JSON.stringify(record, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  }
  renameSync(temporaryDirectory, destination);
  console.log(`Created 2-of-3 demonstration shares under ${destination}.`);
  console.log("This script saw the master key and all three shares. These files do not constitute an independent trustee key ceremony.");
} catch (error) {
  rmSync(temporaryDirectory, { recursive: true, force: true });
  throw error;
}
