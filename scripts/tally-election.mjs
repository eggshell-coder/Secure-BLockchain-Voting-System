import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { addCiphertextVectors } from "../lib/crypto/elgamal.ts";
import { createDecryptionShare, combineThresholdDecryption } from "../lib/crypto/tally.ts";
import { computePublishedTallyResultHash, verifyElectionDataset } from "../lib/crypto/public-verifier.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const [datasetPath, ...args] = process.argv.slice(2);
if (!datasetPath || args.length < 2) {
  throw new Error("Usage: node --experimental-strip-types scripts/tally-election.mjs <public-dataset.json> <trustee-1.json> <trustee-2.json> [trustee-3.json] [--output=tally.json]");
}
const outputArgument = args.find((argument) => argument.startsWith("--output="));
const sharePaths = args.filter((argument) => !argument.startsWith("--output="));
if (sharePaths.length < 2 || sharePaths.length > 3) throw new Error("Provide two or three trustee share files.");
const dataset = JSON.parse(readFileSync(path.resolve(datasetPath), "utf8"));
const verified = await verifyElectionDataset(dataset);
if (verified.ballotCount < 1) throw new Error("Cannot tally an election with no accepted ballots.");

const shares = sharePaths.map((sharePath) => JSON.parse(readFileSync(path.resolve(sharePath), "utf8")));
for (const share of shares) {
  if (share.electionId !== dataset.election.id || share.electionPublicKey !== dataset.election.electionPublicKey ||
      share.scheme !== "ristretto255-exponential-elgamal-v1/shamir-2-of-3" || share.threshold !== 2 || share.totalTrustees !== 3) {
    throw new Error("Trustee share file does not match this election's 2-of-3 key.");
  }
}
if (new Set(shares.map((share) => share.index)).size !== shares.length ||
    shares.some((share) => !Number.isSafeInteger(share.index) || share.index < 1 || share.index > 3)) {
  throw new Error("Trustee share indexes must be unique values from 1 to 3.");
}

const ballots = dataset.ballots.map((row) => row.ballotPayload.ballot);
const aggregates = addCiphertextVectors(ballots.map((ballot) =>
  ballot.selections.map(({ ciphertext }) => ciphertext)
));
const candidates = [];
for (let index = 0; index < dataset.election.candidates.length; index += 1) {
  const candidateId = dataset.election.candidates[index].id;
  const aggregateCiphertext = aggregates[index];
  const decryptionShares = await Promise.all(shares.map((share) => createDecryptionShare(
    dataset.election.id,
    candidateId,
    aggregateCiphertext,
    { index: share.index, secretShare: share.secretShare, publicShare: share.publicShare }
  )));
  const recovered = await combineThresholdDecryption(
    dataset.election.id,
    candidateId,
    aggregateCiphertext,
    decryptionShares,
    dataset.election.electionPublicKey,
    2,
    verified.ballotCount
  );
  candidates.push({
    candidateId,
    aggregateCiphertext,
    decryptionShares,
    count: recovered.count,
    encodedCount: recovered.encodedCount,
    usedIndexes: recovered.usedIndexes
  });
}

const tally = {
  version: 1,
  electionId: dataset.election.id,
  manifestHash: dataset.election.manifestHash,
  acceptedBallotsHead: verified.chainHead,
  ballotCount: verified.ballotCount,
  threshold: 2,
  candidates
};
tally.resultHash = computePublishedTallyResultHash(tally);
const output = outputArgument
  ? path.resolve(outputArgument.slice("--output=".length))
  : path.resolve(root, `tally-${dataset.election.id}.json`);
writeFileSync(output, `${JSON.stringify(tally, null, 2)}\n`, { flag: "wx", mode: 0o600 });
console.log(`Created publicly verifiable tally: ${output}`);
console.log(`Result hash: ${tally.resultHash}`);
console.log("The tally publishes decryption shares and proofs. It does not reveal any individual ballot.");
