import { verifyEncryptedBallot } from "../lib/crypto/proofs.ts";

export async function verifyBallotForElection(ballot, election, now = Date.now()) {
  if (!election || !ballot || typeof ballot !== "object") return { valid: false, reason: "malformed" };
  if (election.status !== "active" || !Number.isFinite(now) ||
      now < Date.parse(election.startsAt) || now >= Date.parse(election.endsAt)) {
    return { valid: false, reason: "election_closed" };
  }
  if (!election.electionPublicKey || election.keyCeremonyStatus !== "prototype_single_key") {
    return { valid: false, reason: "election_key_unavailable" };
  }
  if (ballot.electionId !== election.id) return { valid: false, reason: "wrong_election" };

  const valid = await verifyEncryptedBallot(ballot, {
    electionId: election.id,
    manifestHash: election.manifestHash,
    candidateIds: election.candidates.map((candidate) => candidate.id),
    electionPublicKey: election.electionPublicKey
  });
  return valid
    ? { valid: true, ballotHash: ballot.ballotHash }
    : { valid: false, reason: "invalid_ballot_proof" };
}

export async function acceptVerifiedBallot(ballot, election, persist, { now = Date.now(), nullifier = null } = {}) {
  const verification = await verifyBallotForElection(ballot, election, now);
  if (!verification.valid) return verification;
  if (typeof persist !== "function") throw new TypeError("A ballot persistence function is required.");
  const result = await persist({
    electionId: election.id,
    ballotHash: verification.ballotHash,
    ballot,
    nullifier
  });
  if (result?.duplicate && result?.same_ballot !== true) return { valid: false, reason: "replayed_ballot" };
  if (result?.open === false) return { valid: false, reason: "election_closed" };
  return { valid: true, ballotHash: verification.ballotHash, duplicate: Boolean(result?.duplicate), record: result };
}
