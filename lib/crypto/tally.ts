import { ristretto255 } from "@noble/curves/ed25519.js";
import {
  decodeCiphertext,
  decodePoint,
  decodePublicKey,
  encodePoint,
  hexToBytes,
  normalizeScalar,
  parseScalar,
  pointMultiply,
  pointSubtract,
  publicKeyFromSecret,
  randomScalar,
  recoverBoundedDiscreteLog,
  scalarToHex,
  secureRandomBytes,
  SCALAR_ORDER,
  type Ciphertext,
  type ElectionPublicKey
} from "./elgamal.ts";

const Point = ristretto255.Point;
const encoder = new TextEncoder();

export type TrusteeKeyShare = Readonly<{
  index: number;
  secretShare: string;
  publicShare: string;
}>;

export type DecryptionShare = Readonly<{
  index: number;
  publicShare: string;
  decryptionShare: string;
  proof: Readonly<{ c: string; z: string }>;
}>;

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let value = normalizeScalar(base);
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = (result * value) % modulus;
    value = (value * value) % modulus;
    power >>= 1n;
  }
  return result;
}

function lagrangeCoefficient(index: number, indexes: readonly number[]): bigint {
  let numerator = 1n;
  let denominator = 1n;
  for (const other of indexes) {
    if (other === index) continue;
    numerator = (numerator * BigInt(other)) % SCALAR_ORDER;
    denominator = (denominator * BigInt(other - index)) % SCALAR_ORDER;
  }
  const inverse = modPow(denominator, SCALAR_ORDER - 2n, SCALAR_ORDER);
  return normalizeScalar(numerator * inverse);
}

function pointAddWeighted(
  parts: readonly Readonly<{ point: ReturnType<typeof decodePoint>; coefficient: bigint }> []
) {
  return parts.reduce((sum, part) => sum.add(pointMultiply(part.point, part.coefficient)), Point.ZERO);
}

async function proofChallenge(domain: string, fields: readonly string[]): Promise<bigint> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is required for tally proofs.");
  const transcript = encoder.encode(JSON.stringify([domain, ...fields]));
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-512", transcript));
  let value = 0n;
  for (let index = digest.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(digest[index]!);
  return value % SCALAR_ORDER;
}

function tallyStatement(ciphertext: Ciphertext, decryptionShare: string, publicShare: string) {
  return [ciphertext.c1, ciphertext.c2, decryptionShare, publicShare];
}

function tallyProofContext(
  electionId: string,
  candidateId: string,
  index: number,
  ciphertext: Ciphertext,
  decryptionShare: string,
  publicShare: string,
  t1: string,
  t2: string
): string[] {
  return [electionId, candidateId, String(index), ...tallyStatement(ciphertext, decryptionShare, publicShare), t1, t2];
}

export function createShamirTrusteeShares(
  secretKey: string,
  threshold = 2,
  totalTrustees = 3,
  randomBytes: (length: number) => Uint8Array = secureRandomBytes
): Readonly<{ electionPublicKey: ElectionPublicKey; threshold: number; shares: readonly TrusteeKeyShare[] }> {
  if (!Number.isSafeInteger(threshold) || !Number.isSafeInteger(totalTrustees) ||
      threshold < 2 || totalTrustees < threshold || totalTrustees > 16) {
    throw new RangeError("Trustee key split must use a threshold of at least 2 and no more than 16 shares.");
  }
  const secret = parseScalar(secretKey, false);
  const coefficients = [secret, ...Array.from({ length: threshold - 1 }, () => randomScalar(false, randomBytes))];
  const shares = Array.from({ length: totalTrustees }, (_, offset) => {
    const index = offset + 1;
    let value = 0n;
    let power = 1n;
    for (const coefficient of coefficients) {
      value = normalizeScalar(value + coefficient * power);
      power = normalizeScalar(power * BigInt(index));
    }
    return {
      index,
      secretShare: scalarToHex(value),
      publicShare: encodePoint(pointMultiply(Point.BASE, value))
    };
  });
  return {
    electionPublicKey: publicKeyFromSecret(secretKey),
    threshold,
    shares
  };
}

export async function createDecryptionShare(
  electionId: string,
  candidateId: string,
  ciphertext: Ciphertext,
  keyShare: TrusteeKeyShare,
  randomBytes: (length: number) => Uint8Array = secureRandomBytes
): Promise<DecryptionShare> {
  if (!Number.isSafeInteger(keyShare.index) || keyShare.index < 1) throw new RangeError("Trustee index must be positive.");
  const secret = parseScalar(keyShare.secretShare, false);
  if (encodePoint(pointMultiply(Point.BASE, secret)) !== keyShare.publicShare) {
    throw new Error("Trustee secret share does not match its published public share.");
  }
  const publicShare = decodePoint(keyShare.publicShare);
  const encrypted = decodeCiphertext(ciphertext, true);
  const sharePoint = pointMultiply(encrypted.c1, secret);
  const shareHex = encodePoint(sharePoint);
  const nonce = randomScalar(false, randomBytes);
  const t1 = encodePoint(pointMultiply(Point.BASE, nonce));
  const t2 = encodePoint(pointMultiply(encrypted.c1, nonce));
  const fields = tallyProofContext(electionId, candidateId, keyShare.index, ciphertext,
    shareHex, keyShare.publicShare, t1, t2);
  const challenge = await proofChallenge("evote/ristretto255/threshold-decryption-share/v1", fields);
  const response = normalizeScalar(nonce + challenge * secret);
  return {
    index: keyShare.index,
    publicShare: keyShare.publicShare,
    decryptionShare: shareHex,
    proof: { c: scalarToHex(challenge), z: scalarToHex(response) }
  };
}

export async function verifyDecryptionShare(
  electionId: string,
  candidateId: string,
  ciphertext: Ciphertext,
  share: DecryptionShare
): Promise<boolean> {
  try {
    if (!Number.isSafeInteger(share.index) || share.index < 1) return false;
    const publicShare = decodePoint(share.publicShare);
    const decryptedShare = decodePoint(share.decryptionShare);
    const c = parseScalar(share.proof.c);
    const z = parseScalar(share.proof.z);
    const encrypted = decodeCiphertext(ciphertext, true);
    const t1 = pointSubtract(pointMultiply(Point.BASE, z), pointMultiply(publicShare, c));
    const t2 = pointSubtract(pointMultiply(encrypted.c1, z), pointMultiply(decryptedShare, c));
    const expected = await proofChallenge(
      "evote/ristretto255/threshold-decryption-share/v1",
      tallyProofContext(electionId, candidateId, share.index, ciphertext,
        share.decryptionShare, share.publicShare, encodePoint(t1), encodePoint(t2))
    );
    return c === expected;
  } catch {
    return false;
  }
}

export async function combineThresholdDecryption(
  electionId: string,
  candidateId: string,
  ciphertext: Ciphertext,
  shares: readonly DecryptionShare[],
  electionPublicKey: ElectionPublicKey,
  threshold: number,
  maxCount: number
): Promise<Readonly<{ count: number; encodedCount: string; usedIndexes: readonly number[] }>> {
  if (!Number.isSafeInteger(threshold) || threshold < 2 || shares.length < threshold) {
    throw new RangeError("Not enough distinct trustee decryption shares.");
  }
  const indexes = shares.map((share) => share.index);
  if (new Set(indexes).size !== indexes.length) throw new TypeError("A trustee share may be used only once.");
  for (const share of shares) {
    if (!await verifyDecryptionShare(electionId, candidateId, ciphertext, share)) {
      throw new Error(`Trustee ${share.index} provided an invalid decryption proof.`);
    }
  }

  const selected = [...shares].sort((left, right) => left.index - right.index).slice(0, threshold);
  const selectedIndexes = selected.map((share) => share.index);
  const publicParts = selected.map((share) => ({
    point: decodePoint(share.publicShare),
    coefficient: lagrangeCoefficient(share.index, selectedIndexes)
  }));
  if (!pointAddWeighted(publicParts).equals(decodePublicKey(electionPublicKey))) {
    throw new Error("Trustee public shares do not reconstruct the election public key.");
  }

  const decryptionPoint = pointAddWeighted(selected.map((share) => ({
    point: decodePoint(share.decryptionShare),
    coefficient: lagrangeCoefficient(share.index, selectedIndexes)
  })));
  const encrypted = decodeCiphertext(ciphertext, true);
  const encodedCount = encodePoint(pointSubtract(encrypted.c2, decryptionPoint));
  const count = recoverBoundedDiscreteLog(decodePoint(encodedCount), maxCount);
  return { count, encodedCount, usedIndexes: selectedIndexes };
}
