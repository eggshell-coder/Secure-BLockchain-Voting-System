import { createHash } from "node:crypto";
import { addCiphertextVectors, generateKeyPair } from "../../lib/crypto/elgamal.ts";
import { canonicalJson, encryptOneHotBallot } from "../../lib/crypto/proofs.ts";
import {
  combineThresholdDecryption,
  createDecryptionShare,
  createShamirTrusteeShares
} from "../../lib/crypto/tally.ts";
import {
  computePublishedTallyResultHash,
  verifyElectionDataset,
  verifyPublishedTally
} from "../../lib/crypto/public-verifier.mjs";
import {
  createEncryptedSemaphoreIdentity,
  generateSemaphoreBallotProof
} from "../../lib/crypto/semaphore.ts";
import { createSemaphoreGroup, verifySemaphoreProofForBallot } from "../../server/semaphore-verifier.mjs";

async function main() {
  const electionId = "a9c690c2-4b40-46ca-9d7d-2cd1a3d41328";
  const passphrase = "a secure test passphrase";
  const keyPair = generateKeyPair();
  const candidates = [
    { id: "candidate-a", name: "Candidate A", manifesto: "First candidate" },
    { id: "candidate-b", name: "Candidate B", manifesto: "Second candidate" }
  ];
  const startsAt = "2026-10-24T00:00:00.000Z";
  const endsAt = "2026-10-26T00:00:00.000Z";
  const manifest = {
    electionId,
    title: "Test Election",
    description: "Verifier integration fixture",
    startsAt,
    endsAt,
    electionPublicKey: keyPair.publicKey,
    candidates: candidates.map((candidate, index) => ({
      position: index + 1,
      name: candidate.name,
      manifesto: candidate.manifesto
    }))
  };
  const manifestHash = createHash("sha256").update(JSON.stringify(manifest)).digest("hex");
  const election = {
    id: electionId,
    title: manifest.title,
    description: manifest.description,
    startsAt,
    endsAt,
    status: "closed",
    manifestHash,
    electionPublicKey: keyPair.publicKey,
    keyCeremonyStatus: "prototype_single_key",
    semaphoreGroupRoot: null,
    semaphoreGroupFrozenAt: "2026-10-23T00:00:00.000Z",
    candidates
  };
  const identities = await Promise.all([0, 1, 2].map(() =>
    createEncryptedSemaphoreIdentity(electionId, passphrase)
  ));
  const commitments = identities.map(({ commitment }) => commitment);
  const group = createSemaphoreGroup(commitments);
  election.semaphoreGroupRoot = group.root.toString();
  const ballot = await encryptOneHotBallot({
    electionId,
    manifestHash,
    candidateIds: candidates.map(({ id }) => id),
    choices: [1, 0],
    electionPublicKey: keyPair.publicKey
  });
  const generated = await generateSemaphoreBallotProof(
    identities[0].vault,
    passphrase,
    commitments,
    ballot.ballotHash
  );
  const valid = await verifySemaphoreProofForBallot(generated.proof, electionId, ballot.ballotHash, commitments);
  const wrongSignalValid = await verifySemaphoreProofForBallot(generated.proof,
    electionId, "9d".repeat(32), commitments);
  const wrongElectionValid = await verifySemaphoreProofForBallot(generated.proof,
    "b9c690c2-4b40-46ca-9d7d-2cd1a3d41328", ballot.ballotHash, commitments);

  const previousHash = "00".repeat(32);
  const semaphoreProofHash = createHash("sha256").update(canonicalJson(generated.proof)).digest("hex");
  const recordHash = createHash("sha256").update(Buffer.concat([
    Buffer.from(electionId.replaceAll("-", ""), "hex"),
    Buffer.from("0000000000000001", "hex"),
    Buffer.from(previousHash, "hex"),
    Buffer.from(ballot.ballotHash, "hex"),
    Buffer.from(semaphoreProofHash, "hex"),
    Buffer.from(generated.nullifier, "utf8")
  ])).digest("hex");
  const dataset = {
    version: 1,
    election,
    semaphoreCommitments: commitments,
    ballots: [{
      electionId,
      ballotSequence: "1",
      ballotId: ballot.ballotId,
      ballotHash: ballot.ballotHash,
      ballotPayload: { ballot, semaphoreProof: generated.proof },
      semaphoreProofHash,
      nullifier: generated.nullifier,
      acceptedAt: "2026-10-25T00:00:00.000Z",
      previousHash,
      recordHash
    }],
    chainHead: { lastSequence: "1", lastHash: recordHash }
  };
  const verifiedDataset = await verifyElectionDataset(dataset);
  const badChain = structuredClone(dataset);
  badChain.ballots[0].recordHash = "ab".repeat(32);
  let badChainRejected = false;
  try { await verifyElectionDataset(badChain); } catch { badChainRejected = true; }
  const badEligibilityArtifact = structuredClone(dataset);
  badEligibilityArtifact.ballots[0].semaphoreProofHash = "cd".repeat(32);
  let badEligibilityArtifactRejected = false;
  try { await verifyElectionDataset(badEligibilityArtifact); } catch { badEligibilityArtifactRejected = true; }

  const keySplit = createShamirTrusteeShares(keyPair.secretKey, 2, 3);
  const ballotVectors = dataset.ballots.map((row) => row.ballotPayload.ballot.selections.map(({ ciphertext }) => ciphertext));
  const aggregates = addCiphertextVectors(ballotVectors);
  const tallyCandidates = [];
  for (let index = 0; index < candidates.length; index += 1) {
    const candidateId = candidates[index].id;
    const decryptionShares = await Promise.all(keySplit.shares.slice(0, 2).map((share) =>
      createDecryptionShare(electionId, candidateId, aggregates[index], share)
    ));
    const recovered = await combineThresholdDecryption(
      electionId, candidateId, aggregates[index], decryptionShares, keyPair.publicKey, 2, 1
    );
    tallyCandidates.push({
      candidateId,
      aggregateCiphertext: aggregates[index],
      decryptionShares,
      count: recovered.count,
      encodedCount: recovered.encodedCount,
      usedIndexes: recovered.usedIndexes
    });
  }
  const tally = {
    version: 1,
    electionId,
    manifestHash,
    acceptedBallotsHead: recordHash,
    ballotCount: 1,
    threshold: 2,
    candidates: tallyCandidates
  };
  tally.resultHash = computePublishedTallyResultHash(tally);
  const tallyResult = await verifyPublishedTally(dataset, tally);
  const badTally = structuredClone(tally);
  badTally.candidates[0].count = 0;
  let badTallyRejected = false;
  try { await verifyPublishedTally(dataset, badTally); } catch { badTallyRejected = true; }

  process.stdout.write(`${JSON.stringify({
    valid,
    wrongSignalValid,
    wrongElectionValid,
    nullifier: generated.nullifier,
    datasetValid: verifiedDataset.valid,
    badChainRejected,
    badEligibilityArtifactRejected,
    tallyValid: tallyResult.valid,
    tallyCounts: tallyResult.results.map((item) => item.count),
    badTallyRejected
  })}\n`, () => process.exit(valid && !wrongSignalValid && !wrongElectionValid &&
    verifiedDataset.valid && badChainRejected && badEligibilityArtifactRejected &&
    tallyResult.valid && badTallyRejected ? 0 : 1));
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`, () => process.exit(1));
});
