import { Group } from "@semaphore-protocol/core/group";
import { Identity } from "@semaphore-protocol/core/identity";
import { generateProof } from "@semaphore-protocol/core/proof";

export const SEMAPHORE_SCHEME = "semaphore-v4";
export const SEMAPHORE_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VAULT_VERSION = 1;
const VAULT_ITERATIONS = 310_000;
const encoder = new TextEncoder();

export type EncryptedSemaphoreIdentity = Readonly<{
  version: 1;
  scheme: typeof SEMAPHORE_SCHEME;
  electionId: string;
  commitment: string;
  kdf: "PBKDF2-SHA-256";
  iterations: number;
  salt: string;
  iv: string;
  ciphertext: string;
}>;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string, length: number): Uint8Array {
  if (!new RegExp(`^[a-f0-9]{${length * 2}}$`).test(value)) throw new TypeError("Invalid encrypted identity encoding.");
  return Uint8Array.from({ length }, (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
}

function randomBytes(length: number): Uint8Array {
  if (!globalThis.crypto?.getRandomValues) throw new Error("Secure browser randomness is unavailable.");
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function assertElectionId(electionId: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(electionId)) {
    throw new TypeError("A UUID election ID is required for Semaphore scope separation.");
  }
}

function assertPassphrase(passphrase: string): void {
  if (typeof passphrase !== "string" || passphrase.length < 12 || passphrase.length > 1024) {
    throw new RangeError("Use an identity recovery passphrase with at least 12 characters.");
  }
}

async function deriveVaultKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  assertPassphrase(passphrase);
  const material = await globalThis.crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return globalThis.crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: VAULT_ITERATIONS, hash: "SHA-256" },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

function vaultAad(electionId: string): Uint8Array {
  return encoder.encode(`evote/semaphore-identity-v1/${electionId}`);
}

export function semaphoreElectionScope(electionId: string): bigint {
  assertElectionId(electionId);
  return BigInt(`0x${electionId.replaceAll("-", "")}`);
}

export function semaphoreSignalFromBallotHash(ballotHash: string): bigint {
  if (!/^[a-f0-9]{64}$/.test(ballotHash)) throw new TypeError("A lowercase SHA-256 ballot hash is required.");
  return BigInt(`0x${ballotHash}`);
}

export async function createEncryptedSemaphoreIdentity(
  electionId: string,
  passphrase: string
): Promise<Readonly<{ vault: EncryptedSemaphoreIdentity; commitment: string }>> {
  assertElectionId(electionId);
  assertPassphrase(passphrase);
  const identity = new Identity();
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveVaultKey(passphrase, salt);
  const encrypted = await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: vaultAad(electionId) },
    key, encoder.encode(identity.export()));
  const commitment = identity.commitment.toString();
  return {
    commitment,
    vault: {
      version: VAULT_VERSION,
      scheme: SEMAPHORE_SCHEME,
      electionId,
      commitment,
      kdf: "PBKDF2-SHA-256",
      iterations: VAULT_ITERATIONS,
      salt: bytesToHex(salt),
      iv: bytesToHex(iv),
      ciphertext: bytesToHex(new Uint8Array(encrypted))
    }
  };
}

export async function openEncryptedSemaphoreIdentity(
  vault: EncryptedSemaphoreIdentity,
  passphrase: string
): Promise<InstanceType<typeof Identity>> {
  if (!vault || vault.version !== VAULT_VERSION || vault.scheme !== SEMAPHORE_SCHEME ||
      vault.kdf !== "PBKDF2-SHA-256" || vault.iterations !== VAULT_ITERATIONS) {
    throw new TypeError("Unsupported Semaphore identity vault format.");
  }
  assertElectionId(vault.electionId);
  const salt = hexToBytes(vault.salt, 16);
  const iv = hexToBytes(vault.iv, 12);
  const ciphertext = hexToBytes(vault.ciphertext, (vault.ciphertext?.length ?? 0) / 2);
  const key = await deriveVaultKey(passphrase, salt);
  const plaintext = await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: vaultAad(vault.electionId) },
    key, ciphertext);
  const identity = Identity.import(new TextDecoder().decode(plaintext));
  if (identity.commitment.toString() !== vault.commitment) throw new Error("Identity vault commitment mismatch.");
  return identity;
}

export async function generateSemaphoreBallotProof(
  vault: EncryptedSemaphoreIdentity,
  passphrase: string,
  groupCommitments: readonly string[],
  ballotHash: string
) {
  if (!Array.isArray(groupCommitments) || groupCommitments.length < 3) {
    throw new RangeError("Semaphore anonymity requires at least three enrolled group members.");
  }
  const members = groupCommitments.map((value) => {
    if (typeof value !== "string" || !/^[1-9][0-9]{0,76}$/.test(value)) throw new TypeError("Invalid Semaphore group commitment.");
    const member = BigInt(value);
    if (member >= SEMAPHORE_FIELD_MODULUS) throw new RangeError("Semaphore group commitment is outside the proof field.");
    return member;
  });
  const identity = await openEncryptedSemaphoreIdentity(vault, passphrase);
  const group = new Group(members);
  if (group.indexOf(identity.commitment) < 0) throw new Error("This identity is not enrolled in the election group.");
  const proof = await generateProof(identity, group, semaphoreSignalFromBallotHash(ballotHash),
    semaphoreElectionScope(vault.electionId));
  return { proof, nullifier: proof.nullifier };
}

export function saveSemaphoreIdentityVault(vault: EncryptedSemaphoreIdentity): void {
  if (!globalThis.localStorage) throw new Error("Browser local storage is unavailable.");
  globalThis.localStorage.setItem(`evote:semaphore:${vault.electionId}`, JSON.stringify(vault));
}

export function loadSemaphoreIdentityVault(electionId: string): EncryptedSemaphoreIdentity | null {
  assertElectionId(electionId);
  const stored = globalThis.localStorage?.getItem(`evote:semaphore:${electionId}`);
  if (!stored) return null;
  const vault = JSON.parse(stored) as EncryptedSemaphoreIdentity;
  if (vault.electionId !== electionId) throw new Error("Stored identity belongs to a different election.");
  return vault;
}
