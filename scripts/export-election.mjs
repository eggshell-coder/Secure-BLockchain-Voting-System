import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const electionId = process.argv[2] ?? "";
const outputArgument = process.argv.slice(3).find((argument) => argument.startsWith("--output="));
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(electionId)) {
  throw new Error("Usage: node scripts/export-election.mjs <election-uuid> [--output=public-dataset.json]");
}
const api = (process.env.ELECTION_API_URL ?? "http://localhost:4173").replace(/\/+$/, "");
const response = await fetch(`${api}/api/elections/${encodeURIComponent(electionId)}/accepted-ballots`, {
  headers: { Accept: "application/json" },
  signal: AbortSignal.timeout(30_000)
});
if (!response.ok) throw new Error(`Election export failed with HTTP ${response.status}: ${await response.text()}`);
const dataset = await response.json();
const outputPath = outputArgument
  ? path.resolve(outputArgument.slice("--output=".length))
  : path.resolve(root, `public-election-${electionId}.json`);
writeFileSync(outputPath, `${JSON.stringify(dataset, null, 2)}\n`, { flag: "wx", mode: 0o600 });
console.log(`Saved public election data: ${outputPath}`);
console.log(`It contains ${dataset.ballots.length} ballot records and ${dataset.semaphoreCommitments.length} anonymous group commitments.`);
