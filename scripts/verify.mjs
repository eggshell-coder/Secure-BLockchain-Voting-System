import { readFileSync } from "node:fs";
import path from "node:path";
import { verifyElectionDataset, verifyPublishedTally } from "../lib/crypto/public-verifier.mjs";

const [datasetPath, tallyPath] = process.argv.slice(2);
if (!datasetPath || process.argv.length > 4) {
  throw new Error("Usage: node --experimental-strip-types scripts/verify.mjs <public-dataset.json> [tally.json]");
}
const dataset = JSON.parse(readFileSync(path.resolve(datasetPath), "utf8"));
const verified = await verifyElectionDataset(dataset);
console.log(`Verified ${verified.ballotCount} encrypted ballots, Semaphore proofs, group root, and hash chain.`);
console.log(`Election: ${verified.electionId}`);
console.log(`Ballot-chain head: ${verified.chainHead}`);
if (tallyPath) {
  const tally = JSON.parse(readFileSync(path.resolve(tallyPath), "utf8"));
  const result = await verifyPublishedTally(dataset, tally);
  console.log(`Verified threshold decryption shares and tally result: ${result.resultHash}`);
  for (const item of result.results) console.log(`${item.candidateId}: ${item.count}`);
}
