import { ristretto255 } from "@noble/curves/ed25519.js";
import {
  addCiphertexts,
  bytesToHex,
  decodeCiphertext,
  decodePoint,
  decodePublicKey,
  encodePoint,
  encryptBitWithRandomness,
  normalizeScalar,
  parseScalar,
  pointMultiply,
  pointSubtract,
  randomScalar,
  scalarToHex,
  secureRandomBytes,
  SCALAR_ORDER,
  type Ciphertext,
  type ElectionPublicKey
} from "./elgamal.ts";

const Point = ristretto255.Point;
const encoder = new TextEncoder();
const HASH_ALGORITHM = "SHA-512";
const BALLOT_HASH_ALGORITHM = "SHA-256";

export type ChaumPedersenOrProof = Readonly<{
  c0: string;
  z0: string;
  c1: string;
  z1: string;
}>;

export type ChaumPedersenProof = Readonly<{ c: string; z: string }>;

export type EncryptedSelection = Readonly<{
  candidateId: string;
  ciphertext: Ciphertext;
  proof: ChaumPedersenOrProof;
}>;

export type EncryptedBallot = Readonly<{
  scheme: string;
  electionId: string;
  manifestHash: string;
  ballotId: string;
  electionPublicKey: ElectionPublicKey;
  selections: readonly EncryptedSelection[];
  sumProof: ChaumPedersenProof;
  ballotHash: string;
}>;

type BallotContext = Readonly<{
  electionId: string;
  manifestHash: string;
  ballotId: string;
  candidateId: string;
  candidateIndex: number;
  electionPublicKey: ElectionPublicKey;
}>;

type RandomSource = (length: number) => Uint8Array;

function assertText(value: unknown, name: string, maxLength = 256): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new TypeError(`${name} must be a non-empty string of at most ${maxLength} characters.`);
  }
}

function assertManifestHash(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new TypeError("manifestHash must be a lowercase SHA-256 hex digest.");
  }
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot encode a non-finite number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(record[key])}`
    ).join(",")}}`;
  }
  throw new TypeError("Unsupported value in canonical JSON.");
}

function ballotBody(ballot: Omit<EncryptedBallot, "ballotHash"> | EncryptedBallot) {
  return {
    scheme: ballot.scheme,
    electionId: ballot.electionId,
    manifestHash: ballot.manifestHash,
    ballotId: ballot.ballotId,
    electionPublicKey: ballot.electionPublicKey,
    selections: ballot.selections.map(({ candidateId, ciphertext, proof }) => ({
      candidateId,
      ciphertext: { c1: ciphertext.c1, c2: ciphertext.c2 },
      proof: { c0: proof.c0, z0: proof.z0, c1: proof.c1, z1: proof.z1 }
    })),
    sumProof: { c: ballot.sumProof.c, z: ballot.sumProof.z }
  };
}

export function canonicalEncryptedBallotJson(ballot: EncryptedBallot): string {
  if (!ballot || typeof ballot !== "object") throw new TypeError("An encrypted ballot is required.");
  return canonicalJson(ballotBody(ballot));
}

function uint32(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError("Transcript field is too large.");
  }
  return new Uint8Array([value >>> 24, value >>> 16, value >>> 8, value]);
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function frameTranscript(fields: readonly (string | Uint8Array)[]): Uint8Array {
  const framed: Uint8Array[] = [];
  for (const field of fields) {
    const bytes = typeof field === "string" ? encoder.encode(field) : field;
    framed.push(uint32(bytes.length), bytes);
  }
  return concatBytes(framed);
}

function bytesToBigIntLittleEndian(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) | BigInt(bytes[index]!);
  }
  return result;
}

async function challenge(domain: string, fields: readonly (string | Uint8Array)[]): Promise<bigint> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("Web Crypto is required for ballot proofs.");
  const digest = new Uint8Array(await subtle.digest(HASH_ALGORITHM, frameTranscript([domain, ...fields])));
  // SHA-512 is reduced modulo q; the negligible reduction bias is conventional
  // for Fiat-Shamir challenges over this prime-order group.
  return bytesToBigIntLittleEndian(digest) % SCALAR_ORDER;
}

async function digestHex(algorithm: string, bytes: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("Web Crypto is required to hash ballots.");
  return bytesToHex(new Uint8Array(await subtle.digest(algorithm, bytes)));
}

function canonicalScalar(hex: string, allowZero = true): bigint {
  const scalar = parseScalar(hex, allowZero);
  if (scalarToHex(scalar) !== hex) throw new TypeError("Scalar encoding is not canonical.");
  return scalar;
}

function orTranscriptFields(
  context: BallotContext,
  ciphertext: Ciphertext,
  commitments: readonly [string, string, string, string]
): string[] {
  return [
    context.electionId,
    context.manifestHash,
    context.ballotId,
    context.candidateId,
    String(context.candidateIndex),
    context.electionPublicKey,
    ciphertext.c1,
    ciphertext.c2,
    ...commitments
  ];
}

function messagePoint(bit: 0 | 1) {
  return bit === 1 ? Point.BASE : Point.ZERO;
}

export async function proveCiphertextIsBit(
  context: BallotContext,
  ciphertext: Ciphertext,
  plaintextBit: 0 | 1,
  nonce: bigint,
  randomBytes: RandomSource = secureRandomBytes
): Promise<ChaumPedersenOrProof> {
  if (plaintextBit !== 0 && plaintextBit !== 1) throw new RangeError("Bit proof witness must be 0 or 1.");
  const secretNonce = normalizeScalar(nonce);
  if (secretNonce === 0n) throw new RangeError("The encryption nonce must be non-zero.");
  const publicKey = decodePublicKey(context.electionPublicKey);
  const { c1: A, c2: B } = decodeCiphertext(ciphertext);
  const simulatedBranch = (1 - plaintextBit) as 0 | 1;
  const challenges: bigint[] = [0n, 0n];
  const responses: bigint[] = [0n, 0n];
  const commitments: [string, string, string, string] = ["", "", "", ""];

  const fakeC = randomScalar(true, randomBytes);
  const fakeZ = randomScalar(true, randomBytes);
  challenges[simulatedBranch] = fakeC;
  responses[simulatedBranch] = fakeZ;
  const fakeStatement = pointSubtract(B, messagePoint(simulatedBranch));
  const fakeT1 = pointSubtract(pointMultiply(Point.BASE, fakeZ), pointMultiply(A, fakeC));
  const fakeT2 = pointSubtract(pointMultiply(publicKey, fakeZ), pointMultiply(fakeStatement, fakeC));
  commitments[simulatedBranch * 2] = encodePoint(fakeT1);
  commitments[simulatedBranch * 2 + 1] = encodePoint(fakeT2);

  const witnessNonce = randomScalar(false, randomBytes);
  const realT1 = pointMultiply(Point.BASE, witnessNonce);
  const realT2 = pointMultiply(publicKey, witnessNonce);
  commitments[plaintextBit * 2] = encodePoint(realT1);
  commitments[plaintextBit * 2 + 1] = encodePoint(realT2);

  const totalChallenge = await challenge(
    "evote/ristretto255/elgamal-bit-or-proof/v1",
    orTranscriptFields(context, ciphertext, commitments)
  );
  const realChallenge = normalizeScalar(totalChallenge - fakeC);
  challenges[plaintextBit] = realChallenge;
  responses[plaintextBit] = normalizeScalar(witnessNonce + realChallenge * secretNonce);

  return {
    c0: scalarToHex(challenges[0]!),
    z0: scalarToHex(responses[0]!),
    c1: scalarToHex(challenges[1]!),
    z1: scalarToHex(responses[1]!)
  };
}

export async function verifyCiphertextIsBit(
  context: BallotContext,
  ciphertext: Ciphertext,
  proof: ChaumPedersenOrProof
): Promise<boolean> {
  try {
    assertText(context.electionId, "electionId");
    assertManifestHash(context.manifestHash);
    assertText(context.ballotId, "ballotId");
    assertText(context.candidateId, "candidateId");
    if (!Number.isSafeInteger(context.candidateIndex) || context.candidateIndex < 0) return false;
    const publicKey = decodePublicKey(context.electionPublicKey);
    const { c1: A, c2: B } = decodeCiphertext(ciphertext);
    if (A.is0()) return false;
    const c0 = canonicalScalar(proof.c0);
    const z0 = canonicalScalar(proof.z0);
    const c1 = canonicalScalar(proof.c1);
    const z1 = canonicalScalar(proof.z1);
    const challenges = [c0, c1] as const;
    const responses = [z0, z1] as const;
    const commitments: [string, string, string, string] = ["", "", "", ""];

    for (const bit of [0, 1] as const) {
      const statement = pointSubtract(B, messagePoint(bit));
      const t1 = pointSubtract(pointMultiply(Point.BASE, responses[bit]), pointMultiply(A, challenges[bit]));
      const t2 = pointSubtract(pointMultiply(publicKey, responses[bit]), pointMultiply(statement, challenges[bit]));
      commitments[bit * 2] = encodePoint(t1);
      commitments[bit * 2 + 1] = encodePoint(t2);
    }

    const expected = await challenge(
      "evote/ristretto255/elgamal-bit-or-proof/v1",
      orTranscriptFields(context, ciphertext, commitments)
    );
    return normalizeScalar(c0 + c1) === expected;
  } catch {
    return false;
  }
}

function sumTranscriptFields(
  context: Omit<BallotContext, "candidateId" | "candidateIndex">,
  ciphertext: Ciphertext,
  t1: string,
  t2: string
): string[] {
  return [context.electionId, context.manifestHash, context.ballotId,
    context.electionPublicKey, ciphertext.c1, ciphertext.c2, t1, t2];
}

export async function proveCiphertextSumIsOne(
  context: Omit<BallotContext, "candidateId" | "candidateIndex">,
  ciphertext: Ciphertext,
  totalRandomness: bigint,
  randomBytes: RandomSource = secureRandomBytes
): Promise<ChaumPedersenProof> {
  const publicKey = decodePublicKey(context.electionPublicKey);
  const { c1: A, c2: B } = decodeCiphertext(ciphertext, true);
  const witness = normalizeScalar(totalRandomness);
  if (!A.equals(pointMultiply(Point.BASE, witness)) ||
      !pointSubtract(B, Point.BASE).equals(pointMultiply(publicKey, witness))) {
    throw new Error("Ciphertext aggregate does not match the one-hot proof witness.");
  }
  const nonce = randomScalar(false, randomBytes);
  const t1 = encodePoint(pointMultiply(Point.BASE, nonce));
  const t2 = encodePoint(pointMultiply(publicKey, nonce));
  const c = await challenge("evote/ristretto255/elgamal-sum-one-proof/v1",
    sumTranscriptFields(context, ciphertext, t1, t2));
  return { c: scalarToHex(c), z: scalarToHex(nonce + c * witness) };
}

export async function verifyCiphertextSumIsOne(
  context: Omit<BallotContext, "candidateId" | "candidateIndex">,
  ciphertext: Ciphertext,
  proof: ChaumPedersenProof
): Promise<boolean> {
  try {
    assertText(context.electionId, "electionId");
    assertManifestHash(context.manifestHash);
    assertText(context.ballotId, "ballotId");
    const publicKey = decodePublicKey(context.electionPublicKey);
    const { c1: A, c2: B } = decodeCiphertext(ciphertext, true);
    const c = canonicalScalar(proof.c);
    const z = canonicalScalar(proof.z);
    const t1 = pointSubtract(pointMultiply(Point.BASE, z), pointMultiply(A, c));
    const t2 = pointSubtract(pointMultiply(publicKey, z),
      pointMultiply(pointSubtract(B, Point.BASE), c));
    const t1Hex = encodePoint(t1);
    const t2Hex = encodePoint(t2);
    const expected = await challenge("evote/ristretto255/elgamal-sum-one-proof/v1",
      sumTranscriptFields(context, ciphertext, t1Hex, t2Hex));
    return c === expected;
  } catch {
    return false;
  }
}

export async function encryptOneHotBallot(input: Readonly<{
  electionId: string;
  manifestHash: string;
  candidateIds: readonly string[];
  choices: readonly number[];
  electionPublicKey: ElectionPublicKey;
  randomBytes?: RandomSource;
}>): Promise<EncryptedBallot> {
  assertText(input.electionId, "electionId");
  assertManifestHash(input.manifestHash);
  if (!Array.isArray(input.candidateIds) || input.candidateIds.length < 2 || input.candidateIds.length > 256) {
    throw new RangeError("A ballot must contain between 2 and 256 candidates.");
  }
  if (new Set(input.candidateIds).size !== input.candidateIds.length) {
    throw new TypeError("Candidate IDs must be unique and ordered by the frozen manifest.");
  }
  input.candidateIds.forEach((id, index) => assertText(id, `candidateIds[${index}]`));
  if (!Array.isArray(input.choices) || input.choices.length !== input.candidateIds.length ||
      input.choices.some((choice) => choice !== 0 && choice !== 1) ||
      input.choices.reduce((total, choice) => total + choice, 0) !== 1) {
    throw new RangeError("Choices must be a one-hot vector with exactly one selected candidate.");
  }
  decodePublicKey(input.electionPublicKey);
  const randomBytes = input.randomBytes ?? secureRandomBytes;
  const ballotId = bytesToHex(randomBytes(32));
  if (ballotId.length !== 64) throw new TypeError("The random source returned an invalid ballot ID.");
  const selections: EncryptedSelection[] = [];
  let totalRandomness = 0n;

  for (let index = 0; index < input.candidateIds.length; index += 1) {
    const nonce = randomScalar(false, randomBytes);
    totalRandomness = normalizeScalar(totalRandomness + nonce);
    const candidateId = input.candidateIds[index]!;
    const { ciphertext } = encryptBitWithRandomness(input.electionPublicKey, input.choices[index]!, nonce);
    const context = {
      electionId: input.electionId,
      manifestHash: input.manifestHash,
      ballotId,
      candidateId,
      candidateIndex: index,
      electionPublicKey: input.electionPublicKey
    };
    const proof = await proveCiphertextIsBit(context, ciphertext, input.choices[index] as 0 | 1,
      nonce, randomBytes);
    selections.push({ candidateId, ciphertext, proof });
  }

  const aggregate = addCiphertexts(selections.map(({ ciphertext }) => ciphertext));
  const sumProof = await proveCiphertextSumIsOne({
    electionId: input.electionId,
    manifestHash: input.manifestHash,
    ballotId,
    electionPublicKey: input.electionPublicKey
  }, aggregate, totalRandomness, randomBytes);
  const body = {
    scheme: "ristretto255-exponential-elgamal-v1",
    electionId: input.electionId,
    manifestHash: input.manifestHash,
    ballotId,
    electionPublicKey: input.electionPublicKey,
    selections,
    sumProof
  };
  const ballotHash = await digestHex(BALLOT_HASH_ALGORITHM, encoder.encode(canonicalJson(body)));
  return { ...body, ballotHash };
}

export async function encryptPublishedElectionBallot(
  election: Readonly<{
    id: string;
    manifestHash: string;
    status: string;
    keyCeremonyStatus: string;
    electionPublicKey: string | null;
    candidates: readonly Readonly<{ id: string }>[];
  }>,
  choices: readonly number[],
  randomBytes: RandomSource = secureRandomBytes
): Promise<EncryptedBallot> {
  if (!election || typeof election.id !== "string" || typeof election.manifestHash !== "string") {
    throw new TypeError("A published election manifest is required.");
  }
  if (election.status === "draft") throw new Error("The election manifest is not published yet.");
  if (election.keyCeremonyStatus !== "prototype_single_key" || !election.electionPublicKey) {
    throw new Error("This election has no configured public encryption key.");
  }
  if (!Array.isArray(election.candidates) || election.candidates.length < 2 ||
      election.candidates.some((candidate) => !candidate || typeof candidate.id !== "string")) {
    throw new TypeError("The election manifest has no valid candidate list.");
  }
  return encryptOneHotBallot({
    electionId: election.id,
    manifestHash: election.manifestHash,
    candidateIds: election.candidates.map(({ id }) => id),
    choices,
    electionPublicKey: election.electionPublicKey,
    randomBytes
  });
}

export async function verifyEncryptedBallot(
  ballot: EncryptedBallot,
  expected: Readonly<{ electionId: string; manifestHash: string; candidateIds: readonly string[]; electionPublicKey: string }>
): Promise<boolean> {
  try {
    if (!ballot || ballot.scheme !== "ristretto255-exponential-elgamal-v1" ||
        ballot.electionId !== expected.electionId || ballot.manifestHash !== expected.manifestHash ||
        ballot.electionPublicKey !== expected.electionPublicKey) return false;
    assertText(ballot.electionId, "electionId");
    assertText(ballot.ballotId, "ballotId");
    assertManifestHash(ballot.manifestHash);
    if (!Array.isArray(expected.candidateIds) || expected.candidateIds.length < 2 ||
        expected.candidateIds.length !== ballot.selections.length ||
        new Set(expected.candidateIds).size !== expected.candidateIds.length) return false;
    decodePublicKey(ballot.electionPublicKey);

    const bitProofsValid = await Promise.all(ballot.selections.map(async (selection, index) => {
      if (selection.candidateId !== expected.candidateIds[index]) return false;
      return verifyCiphertextIsBit({
        electionId: ballot.electionId,
        manifestHash: ballot.manifestHash,
        ballotId: ballot.ballotId,
        candidateId: selection.candidateId,
        candidateIndex: index,
        electionPublicKey: ballot.electionPublicKey
      }, selection.ciphertext, selection.proof);
    }));
    if (bitProofsValid.some((valid) => !valid)) return false;

    const aggregate = addCiphertexts(ballot.selections.map(({ ciphertext }) => ciphertext));
    if (!await verifyCiphertextSumIsOne({
      electionId: ballot.electionId,
      manifestHash: ballot.manifestHash,
      ballotId: ballot.ballotId,
      electionPublicKey: ballot.electionPublicKey
    }, aggregate, ballot.sumProof)) return false;

    const calculatedHash = await digestHex(BALLOT_HASH_ALGORITHM,
      encoder.encode(canonicalJson(ballotBody(ballot))));
    return calculatedHash === ballot.ballotHash;
  } catch {
    return false;
  }
}
