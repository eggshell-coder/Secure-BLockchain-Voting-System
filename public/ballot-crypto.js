import {
  encryptOneHotBallot,
  encryptPublishedElectionBallot,
  verifyEncryptedBallot
} from "../lib/crypto/proofs.ts";

// This surface accepts only the frozen election public key. Secret keys and
// per-ballot encryption nonces remain outside the serialized ballot object.
globalThis.votingCrypto = Object.freeze({
  scheme: "ristretto255-exponential-elgamal-v1",
  encryptOneHotBallot,
  encryptPublishedElectionBallot,
  verifyEncryptedBallot
});
