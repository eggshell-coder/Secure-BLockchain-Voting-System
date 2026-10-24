import { createHash } from "node:crypto";
import { addCiphertextVectors } from "./elgamal.ts";
import { verifyEncryptedBallot } from "./proofs.ts";
import { combineThresholdDecryption, verifyDecryptionShare } from "./tally.ts";
import { createSemaphoreGroup, verifySemaphoreProofForBallot } from "../../server/semaphore-verifier.mjs";

const ZERO_HASH = "00".repeat(32);

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot encode a non-finite number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("Unsupported value in canonical JSON.");
}

function hex(value, name) {
  let result = value;
  if (typeof result === "string" && result.startsWith("\\x")) result = result.slice(2);
  if (typeof result === "string" && result.startsWith("0x")) result = result.slice(2);
  if (typeof result !== "string" || !/^[a-f0-9]{64}$/i.test(result)) throw new TypeError(`${name} must be a 32-byte hex value.`);
  return result.toLowerCase();
}

function uuidBytes(value) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value ?? "")) {
    throw new TypeError("Dataset election ID must be a UUID.");
  }
  return Buffer.from(value.replaceAll("-", ""), "hex");
}

function manifestDigest(election) {
  const manifest = {
    electionId: election.id,
    title: election.title,
    description: election.description,
    startsAt: new Date(election.startsAt).toISOString(),
    endsAt: new Date(election.endsAt).toISOString(),
    ...(election.electionPublicKey ? { electionPublicKey: election.electionPublicKey } : {}),
    candidates: election.candidates.map((candidate, index) => ({
      position: index + 1,
      name: candidate.name,
      manifesto: candidate.manifesto
    }))
  };
  return createHash("sha256").update(JSON.stringify(manifest)).digest("hex");
}

function recordDigest(electionId, sequence, previousHash, ballotHash, proofHash, nullifier) {
  const sequenceBytes = Buffer.alloc(8);
  sequenceBytes.writeBigUInt64BE(BigInt(sequence));
  return createHash("sha256").update(Buffer.concat([
    uuidBytes(electionId),
    sequenceBytes,
    Buffer.from(previousHash, "hex"),
    Buffer.from(ballotHash, "hex"),
    Buffer.from(proofHash, "hex"),
    Buffer.from(nullifier, "utf8")
  ])).digest("hex");
}

export function computePublishedTallyResultHash(tally) {
  const body = { ...tally };
  delete body.resultHash;
  return createHash("sha256").update(canonicalJson(body)).digest("hex");
}

function candidateIds(election) {
  if (!Array.isArray(election?.candidates) || election.candidates.length < 2 ||
      election.candidates.some((candidate) => typeof candidate?.id !== "string") ||
      new Set(election.candidates.map((candidate) => candidate.id)).size !== election.candidates.length) {
    throw new TypeError("Election candidate list is malformed.");
  }
  return election.candidates.map((candidate) => candidate.id);
}

export async function verifyElectionDataset(dataset) {
  const election = dataset?.election;
  const ids = candidateIds(election);
  if (dataset.version !== 1 || typeof election.id !== "string" ||
      !/^[a-f0-9]{64}$/.test(election.manifestHash ?? "") ||
      manifestDigest(election) !== election.manifestHash) {
    throw new Error("Published election manifest does not match its hash.");
  }
  if (election.keyCeremonyStatus !== "prototype_single_key" || !election.electionPublicKey) {
    throw new Error("This verifier currently supports only prototype single-key elections.");
  }
  if (!election.semaphoreGroupFrozenAt || !election.semaphoreGroupRoot) {
    throw new Error("Election Semaphore group has not been frozen.");
  }
  const commitments = dataset.semaphoreCommitments;
  const group = createSemaphoreGroup(commitments);
  if (group.root.toString() !== String(election.semaphoreGroupRoot)) {
    throw new Error("Published Semaphore group does not match the frozen root.");
  }
  if (!Array.isArray(dataset.ballots)) throw new TypeError("Dataset ballots must be an array.");

  const seenNullifiers = new Set();
  const seenBallotIds = new Set();
  const seenHashes = new Set();
  let previousHash = ZERO_HASH;
  const verifiedBallots = [];
  const rows = [...dataset.ballots].sort((left, right) => Number(left.ballotSequence) - Number(right.ballotSequence));

  for (let position = 0; position < rows.length; position += 1) {
    const row = rows[position];
    const sequence = Number(row.ballotSequence);
    if (!Number.isSafeInteger(sequence) || sequence !== position + 1 || row.electionId !== election.id) {
      throw new Error(`Ballot row ${position + 1} has a missing or inconsistent sequence/election ID.`);
    }
    const ballot = row.ballotPayload?.ballot;
    const proof = row.ballotPayload?.semaphoreProof;
    const nullifier = String(row.nullifier ?? "");
    if (!/^[1-9][0-9]{0,76}$/.test(nullifier) || seenNullifiers.has(nullifier)) {
      throw new Error(`Ballot row ${sequence} has an invalid or reused nullifier.`);
    }
    if (typeof ballot?.ballotId !== "string" || row.ballotId !== ballot.ballotId || seenBallotIds.has(ballot.ballotId)) {
      throw new Error(`Ballot row ${sequence} has an invalid or reused ballot ID.`);
    }
    if (!await verifyEncryptedBallot(ballot, {
      electionId: election.id,
      manifestHash: election.manifestHash,
      candidateIds: ids,
      electionPublicKey: election.electionPublicKey
    })) throw new Error(`Ballot row ${sequence} failed encrypted ballot proof verification.`);
    if (proof?.nullifier !== nullifier ||
        !await verifySemaphoreProofForBallot(proof, election.id, ballot.ballotHash, commitments)) {
      throw new Error(`Ballot row ${sequence} failed Semaphore membership proof verification.`);
    }
    const proofHash = hex(row.semaphoreProofHash, `ballot ${sequence} Semaphore proof hash`);
    const calculatedProofHash = createHash("sha256").update(canonicalJson(proof)).digest("hex");
    if (proofHash !== calculatedProofHash) throw new Error(`Ballot row ${sequence} Semaphore proof hash is inconsistent.`);

    const ballotHash = hex(row.ballotHash, `ballot ${sequence} digest`);
    if (ballotHash !== ballot.ballotHash || seenHashes.has(ballotHash)) {
      throw new Error(`Ballot row ${sequence} digest is inconsistent or duplicated.`);
    }
    const rowPreviousHash = hex(row.previousHash, `ballot ${sequence} previous hash`);
    const rowRecordHash = hex(row.recordHash, `ballot ${sequence} record hash`);
    if (rowPreviousHash !== previousHash) throw new Error(`Ballot row ${sequence} breaks the hash chain.`);
    const expectedRecordHash = recordDigest(election.id, sequence, previousHash, ballotHash, proofHash, nullifier);
    if (rowRecordHash !== expectedRecordHash) throw new Error(`Ballot row ${sequence} has an invalid chain hash.`);
    previousHash = rowRecordHash;
    seenNullifiers.add(nullifier);
    seenBallotIds.add(ballot.ballotId);
    seenHashes.add(ballotHash);
    verifiedBallots.push(ballot);
  }

  const head = dataset.chainHead ?? { lastSequence: 0, lastHash: ZERO_HASH };
  if (Number(head.lastSequence) !== rows.length || hex(head.lastHash, "chain head") !== previousHash) {
    throw new Error("Published chain head does not match the verified ballot list.");
  }
  const aggregates = rows.length
    ? addCiphertextVectors(verifiedBallots.map((ballot) => ballot.selections.map(({ ciphertext }) => ciphertext)))
    : [];
  return {
    valid: true,
    electionId: election.id,
    ballotCount: rows.length,
    chainHead: previousHash,
    candidateIds: ids,
    aggregates
  };
}

export async function verifyPublishedTally(dataset, tally) {
  const verified = await verifyElectionDataset(dataset);
  if (tally?.version !== 1 || tally.electionId !== verified.electionId ||
      tally.manifestHash !== dataset.election.manifestHash ||
      tally.ballotCount !== verified.ballotCount || tally.acceptedBallotsHead !== verified.chainHead ||
      tally.threshold !== 2 || !Array.isArray(tally.candidates) ||
      tally.candidates.length !== verified.candidateIds.length) {
    throw new Error("Tally metadata does not match the verified election dataset.");
  }
  const resultHash = computePublishedTallyResultHash(tally);
  if (resultHash !== tally.resultHash) throw new Error("Published tally result hash is invalid.");

  const results = [];
  for (let index = 0; index < verified.candidateIds.length; index += 1) {
    const entry = tally.candidates[index];
    const aggregate = verified.aggregates[index];
    if (entry?.candidateId !== verified.candidateIds[index] || !aggregate ||
        entry.aggregateCiphertext?.c1 !== aggregate.c1 || entry.aggregateCiphertext?.c2 !== aggregate.c2) {
      throw new Error(`Tally ciphertext for candidate ${verified.candidateIds[index]} is inconsistent.`);
    }
    if (!Array.isArray(entry.decryptionShares) || entry.decryptionShares.length < tally.threshold) {
      throw new Error(`Tally for candidate ${entry.candidateId} has too few trustee shares.`);
    }
    for (const share of entry.decryptionShares) {
      if (!await verifyDecryptionShare(verified.electionId, entry.candidateId, aggregate, share)) {
        throw new Error(`Invalid decryption proof for candidate ${entry.candidateId}, trustee ${share.index}.`);
      }
    }
    const recovered = await combineThresholdDecryption(
      verified.electionId, entry.candidateId, aggregate, entry.decryptionShares,
      dataset.election.electionPublicKey, tally.threshold, verified.ballotCount
    );
    if (recovered.count !== entry.count || recovered.encodedCount !== entry.encodedCount ||
        JSON.stringify(recovered.usedIndexes) !== JSON.stringify(entry.usedIndexes)) {
      throw new Error(`Published count for candidate ${entry.candidateId} does not match the trustee shares.`);
    }
    results.push({ candidateId: entry.candidateId, count: recovered.count });
  }
  if (verified.ballotCount > 0 && results.reduce((total, result) => total + result.count, 0) !== verified.ballotCount) {
    throw new Error("Tally totals do not equal the number of accepted ballots.");
  }
  return { valid: true, resultHash, ballotCount: verified.ballotCount, results, chainHead: verified.chainHead };
}
