import { Group } from "@semaphore-protocol/core/group";
import { verifyProof } from "@semaphore-protocol/core/proof";

export const SEMAPHORE_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function electionScope(electionId) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(electionId ?? "")) {
    throw new TypeError("A UUID election ID is required.");
  }
  return BigInt(`0x${electionId.replaceAll("-", "")}`);
}

export function semaphoreSignal(ballotHash) {
  if (!/^[a-f0-9]{64}$/.test(ballotHash ?? "")) throw new TypeError("A lowercase SHA-256 ballot hash is required.");
  return BigInt(`0x${ballotHash}`);
}

export function createSemaphoreGroup(commitments, { minimumMembers = 3 } = {}) {
  if (!Array.isArray(commitments) || commitments.length < minimumMembers) {
    throw new RangeError(`At least ${minimumMembers} group commitments are required.`);
  }
  const members = commitments.map((commitment) => {
    if (typeof commitment !== "string" || !/^[1-9][0-9]{0,76}$/.test(commitment)) {
      throw new TypeError("Semaphore commitments must be canonical positive decimal strings.");
    }
    const value = BigInt(commitment);
    if (value >= SEMAPHORE_FIELD_MODULUS) throw new RangeError("Semaphore commitment is outside the proof field.");
    return value;
  });
  if (new Set(members.map(String)).size !== members.length) throw new TypeError("Duplicate Semaphore commitments are not allowed.");
  return new Group(members);
}

export async function verifySemaphoreProofForBallot(proof, electionId, ballotHash, commitments) {
  try {
    const expectedScope = electionScope(electionId).toString();
    const expectedMessage = semaphoreSignal(ballotHash).toString();
    const group = createSemaphoreGroup(commitments);
    if (!proof || typeof proof !== "object" ||
        proof.scope !== expectedScope || proof.message !== expectedMessage ||
        proof.merkleTreeRoot !== group.root.toString() ||
        proof.merkleTreeDepth !== group.depth ||
        typeof proof.nullifier !== "string" || !/^[1-9][0-9]{0,76}$/.test(proof.nullifier)) return false;
    if (BigInt(proof.nullifier) >= SEMAPHORE_FIELD_MODULUS) return false;
    return await verifyProof(proof);
  } catch {
    return false;
  }
}
