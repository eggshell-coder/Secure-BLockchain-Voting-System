import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  addCiphertextVectors,
  decryptCount,
  generateKeyPair
} from "../../lib/crypto/elgamal.ts";
import {
  combineThresholdDecryption,
  createDecryptionShare,
  createShamirTrusteeShares
} from "../../lib/crypto/tally.ts";
import {
  encryptOneHotBallot,
  encryptPublishedElectionBallot,
  verifyEncryptedBallot
} from "../../lib/crypto/proofs.ts";
import {
  createEncryptedSemaphoreIdentity,
  generateSemaphoreBallotProof,
  openEncryptedSemaphoreIdentity,
  semaphoreElectionScope
} from "../../lib/crypto/semaphore.ts";
import { acceptVerifiedBallot, verifyBallotForElection } from "../../server/ballot-verifier.mjs";
import {
  createSemaphoreGroup,
  electionScope,
  semaphoreSignal,
  verifySemaphoreProofForBallot
} from "../../server/semaphore-verifier.mjs";
import { shuffleCommitments } from "../../server/semaphore-enrollment.mjs";

const election = {
  electionId: "ewsu-2026-union",
  manifestHash: "a1".repeat(32),
  candidateIds: ["candidate-a", "candidate-b", "candidate-c"]
};
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

async function makeBallot(publicKey, choices = [0, 1, 0]) {
  return encryptOneHotBallot({ ...election, choices, electionPublicKey: publicKey });
}

test("client produces a valid encrypted one-hot ballot without serializing plaintext or nonces", async () => {
  const keyPair = generateKeyPair();
  const ballot = await makeBallot(keyPair.publicKey);

  assert.equal(await verifyEncryptedBallot(ballot, {
    ...election,
    electionPublicKey: keyPair.publicKey
  }), true);
  assert.equal(Object.hasOwn(ballot, "choices"), false);
  assert.equal(JSON.stringify(ballot).includes("randomness"), false);
  assert.equal(JSON.stringify(ballot).includes("secretKey"), false);
  assert.equal(ballot.selections.length, election.candidateIds.length);
});

test("client rejects non-binary, all-zero, multi-choice, and mismatched ballots", async () => {
  const keyPair = generateKeyPair();
  for (const choices of [[1, 1, 0], [2, 0, 0], [0, 0, 0], [1, 0]]) {
    await assert.rejects(() => makeBallot(keyPair.publicKey, choices));
  }
  await assert.rejects(() => encryptOneHotBallot({
    ...election,
    candidateIds: ["same", "same"],
    choices: [1, 0],
    electionPublicKey: keyPair.publicKey
  }));
});

test("four-candidate ballots reject [1,1,0,0], [2,0,0,0], and [0,0,0,0]", async () => {
  const keyPair = generateKeyPair();
  const fourCandidates = ["a", "b", "c", "d"];
  for (const choices of [[1, 1, 0, 0], [2, 0, 0, 0], [0, 0, 0, 0]]) {
    await assert.rejects(() => encryptOneHotBallot({
      ...election,
      candidateIds: fourCandidates,
      choices,
      electionPublicKey: keyPair.publicKey
    }));
  }
});

test("published-election encryption refuses a missing key or an unfrozen draft", async () => {
  const noKey = {
    ...election,
    id: election.electionId,
    status: "active",
    keyCeremonyStatus: "not_started",
    electionPublicKey: null,
    candidates: election.candidateIds.map((id) => ({ id }))
  };
  await assert.rejects(
    () => encryptPublishedElectionBallot(noKey, [1, 0, 0]),
    /no configured public encryption key/
  );

  const keyPair = generateKeyPair();
  await assert.rejects(
    () => encryptPublishedElectionBallot({
      ...noKey,
      status: "draft",
      keyCeremonyStatus: "prototype_single_key",
      electionPublicKey: keyPair.publicKey
    }, [1, 0, 0]),
    /not published yet/
  );

  const ballot = await encryptPublishedElectionBallot({
    ...noKey,
    keyCeremonyStatus: "prototype_single_key",
    electionPublicKey: keyPair.publicKey
  }, [1, 0, 0]);
  assert.equal(ballot.electionPublicKey, keyPair.publicKey);
  assert.equal(ballot.electionId, noKey.id);
});

test("admin keygen stores the secret locally and sends only the public key", async () => {
  const electionId = "f753497a-64a0-4017-9a8e-cdd0837bf86f";
  const dataDirectory = path.join(projectRoot, "data");
  await mkdir(dataDirectory, { recursive: true });
  const keyDirectory = await mkdtemp(path.join(dataDirectory, "election-keygen-test-"));
  let publicKeyPosted = null;
  let requests = 0;
  const server = http.createServer(async (request, response) => {
    requests += 1;
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const bodyText = Buffer.concat(chunks).toString("utf8");
    if (request.url === "/api/admin/login") {
      assert.equal(request.method, "POST");
      assert.equal(JSON.parse(bodyText).email, "admin@example.test");
      response.writeHead(200, { "Content-Type": "application/json", "Set-Cookie": "session=mock-session; HttpOnly; Path=/" });
      response.end(JSON.stringify({ signedIn: true }));
      return;
    }
    if (request.url === "/api/admin/elections") {
      assert.equal(request.method, "GET");
      assert.equal(request.headers.cookie, "session=mock-session");
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ elections: [{
        id: electionId,
        status: "draft",
        electionPublicKey: null,
        keyCeremonyStatus: "not_started"
      }] }));
      return;
    }
    assert.equal(request.url, `/api/admin/elections/${electionId}/prototype-key`);
    assert.equal(request.method, "POST");
    assert.equal(request.headers.cookie, "session=mock-session");
    const payload = JSON.parse(bodyText);
    assert.deepEqual(Object.keys(payload), ["publicKey"]);
    assert.match(payload.publicKey, /^[a-f0-9]{64}$/);
    publicKeyPosted = payload.publicKey;
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ electionId, electionPublicKey: publicKeyPosted, keyCeremonyStatus: "prototype_single_key" }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    const child = spawn(process.execPath, ["--experimental-strip-types", "scripts/generate-election-key.mjs", electionId], {
      cwd: projectRoot,
      env: {
        ...process.env,
        ADMIN_EMAIL: "admin@example.test",
        ADMIN_PASSWORD: "test-password",
        APP_BASE_URL: baseUrl,
        ELECTION_KEY_DIR: keyDirectory
      },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    const exitCode = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    assert.equal(exitCode, 0, stderr);
    assert.equal(requests, 3);
    const saved = JSON.parse(await readFile(path.join(keyDirectory, `${electionId}.json`), "utf8"));
    assert.equal(saved.electionId, electionId);
    assert.equal(saved.publicKey, publicKeyPosted);
    assert.equal(typeof saved.secretKey, "string");
    assert.equal(stdout.includes(saved.secretKey), false);
    assert.match(stdout, /Public key fingerprint \(SHA-256\): [a-f0-9]{64}/);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(keyDirectory, { recursive: true, force: true });
  }
});

test("server ballot gate binds the election, checks opening time, and rejects tampering and replay", async () => {
  const keyPair = generateKeyPair();
  const ballot = await makeBallot(keyPair.publicKey);
  const openElection = {
    id: election.electionId,
    status: "active",
    startsAt: "2026-10-24T00:00:00.000Z",
    endsAt: "2026-10-26T00:00:00.000Z",
    manifestHash: election.manifestHash,
    electionPublicKey: keyPair.publicKey,
    keyCeremonyStatus: "prototype_single_key",
    candidates: election.candidateIds.map((id) => ({ id }))
  };
  const now = Date.parse("2026-10-25T00:00:00.000Z");

  assert.equal((await verifyBallotForElection(ballot, openElection, now)).valid, true);
  assert.deepEqual(await verifyBallotForElection(ballot, {
    ...openElection,
    id: "another-election"
  }, now), { valid: false, reason: "wrong_election" });
  assert.deepEqual(await verifyBallotForElection(ballot, openElection, Date.parse(openElection.startsAt) - 1),
    { valid: false, reason: "election_closed" });
  assert.deepEqual(await verifyBallotForElection(ballot, openElection, Date.parse(openElection.endsAt)),
    { valid: false, reason: "election_closed" });

  const tampered = structuredClone(ballot);
  tampered.selections[0].ciphertext.c2 = tampered.selections[1].ciphertext.c2;
  assert.deepEqual(await verifyBallotForElection(tampered, openElection, now),
    { valid: false, reason: "invalid_ballot_proof" });

  let saved = null;
  const persistence = async ({ ballotHash, nullifier }) => {
    if (saved?.nullifier === nullifier) {
      return { duplicate: true, same_ballot: saved.ballotHash === ballotHash };
    }
    saved = { ballotHash, nullifier };
    return { duplicate: false, sequence: 1 };
  };
  assert.equal((await acceptVerifiedBallot(ballot, openElection, persistence, { now, nullifier: "777" })).valid, true);
  const sameBallotRetry = await acceptVerifiedBallot(ballot, openElection, persistence, { now, nullifier: "777" });
  assert.equal(sameBallotRetry.valid, true);
  assert.equal(sameBallotRetry.duplicate, true);

  const secondBallot = await makeBallot(keyPair.publicKey, [1, 0, 0]);
  assert.deepEqual(await acceptVerifiedBallot(secondBallot, openElection, persistence, { now, nullifier: "777" }),
    { valid: false, reason: "replayed_ballot" });
});

test("Semaphore identity stays in an encrypted local vault and scope is election-specific", async () => {
  const electionId = "f753497a-64a0-4017-9a8e-cdd0837bf86f";
  const passphrase = "correct horse battery staple";
  const { vault, commitment } = await createEncryptedSemaphoreIdentity(electionId, passphrase);
  const identity = await openEncryptedSemaphoreIdentity(vault, passphrase);
  assert.equal(identity.commitment.toString(), commitment);
  assert.equal(JSON.stringify(vault).includes(identity.export()), false);
  await assert.rejects(() => openEncryptedSemaphoreIdentity(vault, "wrong password phrase"));
  assert.notEqual(semaphoreElectionScope(electionId), semaphoreElectionScope("f753497a-64a0-4017-9a8e-cdd0837bf870"));
  await assert.rejects(() => generateSemaphoreBallotProof(vault, passphrase, [commitment], "ab".repeat(32)),
    /at least three/);
});

test("Semaphore enrollment and group tables have no voter-commitment join key or timestamp link", async () => {
  const initialSchema = await readFile(path.join(projectRoot,
    "supabase/migrations/20261025143000_semaphore_eligibility.sql"), "utf8");
  const privacyMigration = await readFile(path.join(projectRoot,
    "supabase/migrations/20261025190000_blind_semaphore_enrollment.sql"), "utf8");
  const serverSource = await readFile(path.join(projectRoot, "server/index.mjs"), "utf8");
  const shuffleSource = await readFile(path.join(projectRoot, "server/semaphore-enrollment.mjs"), "utf8");
  const columns = (source, table) => {
    const match = source.match(new RegExp(`CREATE TABLE public\\.${table} \\(([\\s\\S]*?)\\n\\);`));
    assert.ok(match, `Could not find table ${table}.`);
    return match[1].split(/,\r?\n/)
      .map((line) => line.trim().match(/^([a-z_]+)\s+(?:uuid|integer|numeric|timestamptz)\b/i)?.[1])
      .filter(Boolean);
  };
  const issuanceColumns = new Set(columns(initialSchema, "semaphore_credential_issuances"));
  const groupColumns = new Set(columns(initialSchema, "semaphore_group_members"));
  const pendingColumns = columns(privacyMigration, "semaphore_pending_commitments");
  assert.match(privacyMigration, /ALTER TABLE public\.semaphore_credential_issuances DROP COLUMN issued_at/);
  assert.match(privacyMigration, /ALTER TABLE public\.semaphore_group_members DROP COLUMN added_at/);
  assert.match(privacyMigration, /DROP COLUMN eligibility_commitment/);
  assert.match(privacyMigration, /DROP COLUMN credential_issued_at/);
  issuanceColumns.delete("issued_at");
  groupColumns.delete("added_at");
  assert.deepEqual([...issuanceColumns].filter((column) => groupColumns.has(column) && column !== "election_id"), []);
  assert.ok(issuanceColumns.has("voter_id"));
  assert.ok(groupColumns.has("identity_commitment"));
  assert.match(privacyMigration, /CREATE TABLE public\.semaphore_pending_commitments/);
  assert.deepEqual(pendingColumns, ["election_id", "identity_commitment"]);
  assert.match(privacyMigration, /CREATE FUNCTION public\.freeze_semaphore_group/);
  assert.match(shuffleSource, /randomInt/);
  assert.match(serverSource, /p_commitments: randomizedCommitments/);

  const logLines = serverSource.split(/\r?\n/).filter((line) => /console\.(?:log|warn|error|info)/.test(line));
  assert.ok(logLines.every((line) => !/authUser\.id|commitment/i.test(line)));
  assert.deepEqual(shuffleCommitments(["11", "22", "33"], (max) => max - 1), ["11", "22", "33"]);
  assert.deepEqual(shuffleCommitments(["11", "22", "33"], () => 0), ["22", "33", "11"]);
});

test("Semaphore server verifier binds the signal, election scope, and current group root", async () => {
  const electionId = "f753497a-64a0-4017-9a8e-cdd0837bf86f";
  const commitments = await Promise.all([0, 1, 2].map(async () =>
    (await createEncryptedSemaphoreIdentity(electionId, "a secure test passphrase")).commitment
  ));
  const group = createSemaphoreGroup(commitments);
  const proof = {
    scope: electionScope(electionId).toString(),
    message: semaphoreSignal("ab".repeat(32)).toString(),
    merkleTreeRoot: group.root.toString(),
    merkleTreeDepth: group.depth,
    nullifier: "1",
    points: []
  };

  assert.equal(await verifySemaphoreProofForBallot({ ...proof, scope: "1" }, electionId, "ab".repeat(32), commitments), false);
  assert.equal(await verifySemaphoreProofForBallot(proof, "another-election", "ab".repeat(32), commitments), false);
  assert.equal(await verifySemaphoreProofForBallot({ ...proof, message: "1" }, electionId, "cd".repeat(32), commitments), false);
  assert.equal(await verifySemaphoreProofForBallot(proof, electionId, "ab".repeat(32), [commitments[0]]), false);
});

test("Semaphore V4 proof verifies for enrolled membership and the encrypted ballot signal", { timeout: 180_000 }, async () => {
  const child = spawn(process.execPath, ["--experimental-strip-types", "tests/crypto/semaphore-proof-child.mjs"], {
    cwd: projectRoot,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  const exitCode = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  assert.equal(exitCode, 0, stderr || stdout);
  const result = JSON.parse(stdout.trim().split(/\r?\n/).at(-1));
  assert.equal(result.valid, true);
  assert.equal(result.wrongSignalValid, false);
  assert.equal(result.wrongElectionValid, false);
  assert.equal(typeof result.nullifier, "string");
  assert.equal(result.datasetValid, true);
  assert.equal(result.badChainRejected, true);
  assert.equal(result.badEligibilityArtifactRejected, true);
  assert.equal(result.tallyValid, true);
  assert.deepEqual(result.tallyCounts, [1, 0]);
  assert.equal(result.badTallyRejected, true);
});

test("verifier rejects tampered ciphertexts, proofs, manifests, and election keys", async () => {
  const keyPair = generateKeyPair();
  const ballot = await makeBallot(keyPair.publicKey);
  const expected = { ...election, electionPublicKey: keyPair.publicKey };

  const badCiphertext = structuredClone(ballot);
  badCiphertext.selections[0].ciphertext.c2 = badCiphertext.selections[1].ciphertext.c2;
  assert.equal(await verifyEncryptedBallot(badCiphertext, expected), false);

  const identityPoint = structuredClone(ballot);
  identityPoint.selections[0].ciphertext.c1 = "00".repeat(32);
  assert.equal(await verifyEncryptedBallot(identityPoint, expected), false);

  const malformedPoint = structuredClone(ballot);
  malformedPoint.selections[0].ciphertext.c1 = "ff".repeat(32);
  assert.equal(await verifyEncryptedBallot(malformedPoint, expected), false);

  const badProof = structuredClone(ballot);
  badProof.selections[0].proof.z0 = "00".repeat(32);
  assert.equal(await verifyEncryptedBallot(badProof, expected), false);

  assert.equal(await verifyEncryptedBallot(ballot, {
    ...expected,
    manifestHash: "b2".repeat(32)
  }), false);
  assert.equal(await verifyEncryptedBallot(ballot, {
    ...expected,
    electionPublicKey: generateKeyPair().publicKey
  }), false);
});

test("homomorphic aggregation decrypts only the candidate totals in this prototype", async () => {
  const keyPair = generateKeyPair();
  const choices = [[1, 0, 0], [0, 1, 0], [0, 1, 0], [0, 0, 1]];
  const ballots = await Promise.all(choices.map((choice) => makeBallot(keyPair.publicKey, choice)));
  const totals = addCiphertextVectors(ballots.map((ballot) =>
    ballot.selections.map(({ ciphertext }) => ciphertext)
  ));

  assert.deepEqual(totals.map((ciphertext) => decryptCount(ciphertext, keyPair.secretKey, choices.length)),
    [1, 2, 1]);
});

test("2-of-3 trustee shares prove and recover only aggregate candidate counts", async () => {
  const keyPair = generateKeyPair();
  const split = createShamirTrusteeShares(keyPair.secretKey, 2, 3);
  assert.equal(split.electionPublicKey, keyPair.publicKey);
  const choices = [[1, 0], [0, 1], [0, 1], [0, 1]];
  const ballots = await Promise.all(choices.map((choice) => encryptOneHotBallot({
    electionId: "threshold-test-election",
    manifestHash: "a1".repeat(32),
    candidateIds: ["candidate-a", "candidate-b"],
    choices: choice,
    electionPublicKey: keyPair.publicKey
  })));
  const aggregates = addCiphertextVectors(ballots.map((ballot) => ballot.selections.map(({ ciphertext }) => ciphertext)));
  for (let index = 0; index < aggregates.length; index += 1) {
    const candidateId = `candidate-${index === 0 ? "a" : "b"}`;
    const shares = await Promise.all(split.shares.slice(0, 2).map((share) =>
      createDecryptionShare("threshold-test-election", candidateId, aggregates[index], share)
    ));
    const recovered = await combineThresholdDecryption(
      "threshold-test-election", candidateId, aggregates[index], shares, keyPair.publicKey, 2, ballots.length
    );
    assert.equal(recovered.count, index === 0 ? 1 : 3);
    const corrupted = { ...shares[0], proof: { ...shares[0].proof, z: "00".repeat(32) } };
    await assert.rejects(() => combineThresholdDecryption(
      "threshold-test-election", candidateId, aggregates[index], [corrupted, shares[1]], keyPair.publicKey, 2, ballots.length
    ));
  }
});
