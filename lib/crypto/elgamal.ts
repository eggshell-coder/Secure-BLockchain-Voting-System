import { ristretto255 } from "@noble/curves/ed25519.js";

export const ELGAMAL_SCHEME = "ristretto255-exponential-elgamal-v1";
export type ElectionPublicKey = string;
export type Ciphertext = Readonly<{ c1: string; c2: string }>;
export type ElectionKeyPair = Readonly<{ publicKey: ElectionPublicKey; secretKey: string }>;

const Point = ristretto255.Point;
const Fn = Point.Fn;
export const SCALAR_ORDER = Fn.ORDER;

export function secureRandomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 1 || length > 65_536) {
    throw new RangeError("Random byte length must be between 1 and 65536.");
  }
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.getRandomValues) {
    throw new Error("A cryptographically secure browser or Node.js random source is required.");
  }
  return webCrypto.getRandomValues(new Uint8Array(length));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string, expectedLength?: number): Uint8Array {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new TypeError("Expected an even-length hexadecimal string.");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new RangeError("Hex value has an unexpected byte length.");
  }
  return bytes;
}

export function normalizeScalar(value: bigint): bigint {
  return ((value % SCALAR_ORDER) + SCALAR_ORDER) % SCALAR_ORDER;
}

export function randomScalar(
  allowZero = false,
  randomBytes: (length: number) => Uint8Array = secureRandomBytes
): bigint {
  // Rejection sampling gives a uniform scalar; reducing arbitrary 256-bit
  // values modulo q would introduce avoidable bias.
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    const bytes = randomBytes(32);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
      throw new TypeError("The random source must return exactly 32 bytes.");
    }
    try {
      const scalar = Fn.fromBytes(bytes);
      if (allowZero || scalar !== 0n) return scalar;
    } catch {
      // A non-canonical 32-byte string is rejected and sampled again.
    }
  }
  throw new Error("Could not sample a canonical Ristretto255 scalar.");
}

export function scalarToHex(value: bigint): string {
  return bytesToHex(Fn.toBytes(normalizeScalar(value)));
}

export function parseScalar(hex: string, allowZero = true): bigint {
  const scalar = Fn.fromBytes(hexToBytes(hex, 32));
  if (!allowZero && scalar === 0n) throw new RangeError("Zero is not allowed for this scalar.");
  return scalar;
}

export function pointMultiply(point: InstanceType<typeof Point>, scalar: bigint) {
  const value = normalizeScalar(scalar);
  return value === 0n ? Point.ZERO : point.multiply(value);
}

export function pointSubtract(
  left: InstanceType<typeof Point>,
  right: InstanceType<typeof Point>
) {
  return left.add(right.negate());
}

export function decodePoint(hex: string, allowZero = true) {
  const point = Point.fromBytes(hexToBytes(hex, 32));
  if (point.is0()) {
    if (!allowZero) throw new RangeError("The identity point is not allowed here.");
    return point;
  }
  point.assertValidity();
  return point;
}

export function decodePublicKey(publicKey: ElectionPublicKey) {
  return decodePoint(publicKey, false);
}

export function encodePoint(point: InstanceType<typeof Point>): string {
  if (!point.is0()) point.assertValidity();
  return bytesToHex(point.toBytes());
}

export function generateKeyPair(
  randomBytes: (length: number) => Uint8Array = secureRandomBytes
): ElectionKeyPair {
  const secret = randomScalar(false, randomBytes);
  const publicPoint = pointMultiply(Point.BASE, secret);
  return {
    publicKey: encodePoint(publicPoint),
    secretKey: scalarToHex(secret)
  };
}

export function publicKeyFromSecret(secretKey: string): ElectionPublicKey {
  const secret = parseScalar(secretKey, false);
  return encodePoint(pointMultiply(Point.BASE, secret));
}

export function encryptBitWithRandomness(
  publicKey: ElectionPublicKey,
  plaintextBit: number,
  randomness: bigint
): Readonly<{ ciphertext: Ciphertext; randomness: bigint }> {
  if (plaintextBit !== 0 && plaintextBit !== 1) {
    throw new RangeError("A ballot selection must be exactly 0 or 1.");
  }
  const secretNonce = normalizeScalar(randomness);
  if (secretNonce === 0n) throw new RangeError("Encryption randomness must be non-zero.");
  const Y = decodePublicKey(publicKey);
  const c1 = pointMultiply(Point.BASE, secretNonce);
  const messagePoint = plaintextBit === 1 ? Point.BASE : Point.ZERO;
  const c2 = messagePoint.add(pointMultiply(Y, secretNonce));
  return {
    ciphertext: { c1: encodePoint(c1), c2: encodePoint(c2) },
    randomness: secretNonce
  };
}

export function encryptBit(
  publicKey: ElectionPublicKey,
  plaintextBit: number,
  randomBytes: (length: number) => Uint8Array = secureRandomBytes
): Ciphertext {
  const nonce = randomScalar(false, randomBytes);
  return encryptBitWithRandomness(publicKey, plaintextBit, nonce).ciphertext;
}

export function decodeCiphertext(ciphertext: Ciphertext, allowIdentityC1 = false) {
  if (!ciphertext || typeof ciphertext.c1 !== "string" || typeof ciphertext.c2 !== "string") {
    throw new TypeError("Malformed ElGamal ciphertext.");
  }
  return {
    // Individual ballot ciphertexts must have non-zero randomness. Aggregated
    // ciphertexts may legitimately have an identity first component if the
    // randomizers sum to zero modulo the group order.
    c1: decodePoint(ciphertext.c1, allowIdentityC1),
    c2: decodePoint(ciphertext.c2)
  };
}

export function addCiphertexts(ciphertexts: readonly Ciphertext[]): Ciphertext {
  if (!Array.isArray(ciphertexts) || ciphertexts.length === 0) {
    throw new RangeError("At least one ciphertext is required for aggregation.");
  }
  let c1 = Point.ZERO;
  let c2 = Point.ZERO;
  for (const ciphertext of ciphertexts) {
    const decoded = decodeCiphertext(ciphertext, true);
    c1 = c1.add(decoded.c1);
    c2 = c2.add(decoded.c2);
  }
  return { c1: encodePoint(c1), c2: encodePoint(c2) };
}

export function addCiphertextVectors(
  ballots: readonly (readonly Ciphertext[])[]
): Ciphertext[] {
  if (!Array.isArray(ballots) || ballots.length === 0) {
    throw new RangeError("At least one ballot is required for aggregation.");
  }
  const width = ballots[0]?.length ?? 0;
  if (width < 2 || ballots.some((ballot) => ballot.length !== width)) {
    throw new RangeError("All ballots must have the same non-empty candidate vector.");
  }
  return Array.from({ length: width }, (_, index) =>
    addCiphertexts(ballots.map((ballot) => ballot[index]!))
  );
}

export function decryptToPoint(ciphertext: Ciphertext, secretKey: string) {
  const secret = parseScalar(secretKey, false);
  const decoded = decodeCiphertext(ciphertext, true);
  return pointSubtract(decoded.c2, pointMultiply(decoded.c1, secret));
}

export function recoverBoundedDiscreteLog(
  encodedCount: InstanceType<typeof Point>,
  maxCount: number
): number {
  if (!Number.isSafeInteger(maxCount) || maxCount < 0 || maxCount > 1_000_000) {
    throw new RangeError("The tally search bound must be between 0 and 1,000,000.");
  }
  let candidate = Point.ZERO;
  for (let count = 0; count <= maxCount; count += 1) {
    if (candidate.equals(encodedCount)) return count;
    candidate = candidate.add(Point.BASE);
  }
  throw new Error("The decrypted tally is outside the supplied voter-count bound.");
}

export function decryptCount(
  ciphertext: Ciphertext,
  secretKey: string,
  maxCount: number
): number {
  return recoverBoundedDiscreteLog(decryptToPoint(ciphertext, secretKey), maxCount);
}
