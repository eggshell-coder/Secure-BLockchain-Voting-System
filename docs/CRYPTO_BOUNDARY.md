# Cryptographic integration boundary

The application deliberately reports voting as unavailable until all of these components are real and reviewed:

1. **Anonymous credential issuance:** one eligible credential per voter without retaining a voter-to-identity-commitment map.
2. **Membership proof:** an audited Semaphore-compatible proof that binds the group root, election scope, nullifier, and encrypted-ballot digest.
3. **Ballot encryption:** randomized encryption to an election public key managed by independent trustees.
4. **Ballot-validity proof:** public proof that the ciphertext encodes exactly one selection from the frozen manifest.
5. **Threshold tally:** aggregation of ciphertexts and threshold decryption of the aggregate only, with verifiable decryption shares.
6. **Independent verifier:** reproducible checking of manifest, accepted ballots, proof artifacts, and tally.

The ballot-acceptance event must make the ciphertext bytes available to the public tally process (or point to a separately verified data-availability layer). The on-chain commitment alone cannot be used to recompute an encrypted tally. Publishing ciphertext in an event costs transaction data and must be included in gas and capacity estimates.

No development mock should return `true` for proof verification in a user-facing deployment. A passing demo-mode proof is not evidence of eligibility, secrecy, or tally correctness.
