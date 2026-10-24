import {
  createEncryptedSemaphoreIdentity,
  generateSemaphoreBallotProof,
  loadSemaphoreIdentityVault,
  saveSemaphoreIdentityVault,
  semaphoreElectionScope
} from "../lib/crypto/semaphore.ts";

globalThis.votingSemaphore = Object.freeze({
  createEncryptedSemaphoreIdentity,
  generateSemaphoreBallotProof,
  loadSemaphoreIdentityVault,
  saveSemaphoreIdentityVault,
  semaphoreElectionScope
});
