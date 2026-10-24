# Build plan and completion gates

## Implemented prototype scope

- Supabase Auth registration, registrar approval, administrator election management, and Postgres-backed audit events.
- Frozen election manifests with a prototype Ristretto255 ElGamal public key.
- Browser one-hot exponential ElGamal encryption, disjunctive Chaum-Pedersen bit proofs, and sum-equals-one proof.
- Browser-held, passphrase-encrypted Semaphore V4 identity; approved-voter commitments staged without timestamps; CSPRNG-shuffled insertion at group freeze; frozen root and server-side eligibility proof checks.
- Server-side ballot proof verifier and scheduled/open-window checks.
- Append-only accepted-ballot table, unique election-scoped nullifier, and serialized per-election SHA-256 chain RPC.
- Solidity ballot box that stores encrypted ballot bytes and accepts only an EIP-712 attestation from its configured verification authority.
- 2-of-3 Shamir share math, aggregate-only homomorphic tally, Chaum-Pedersen decryption-share proofs, tally CLI, public election export and independent verifier.
- Misuse tests for invalid one-hot ballots, malformed points, wrong election, late ballot, replay/nullifier, Semaphore proof binding, hash-chain tampering, and threshold tally tampering.

**Ballot submission remains disabled.** `ENABLE_BALLOT_ACCEPTANCE=false` and the hard-coded `cryptoReadiness.votingEnabled=false` both block the relay. A code implementation passing tests is not equivalent to production readiness.

## Work still required before a real election

| Phase | Deliverables | Completion gate |
| --- | --- | --- |
| 1. Governance and eligibility | Election rules, authoritative student roster, appeal process, privacy and retention policy, accessibility and incident procedures | Election authority approves the written protocol and role separation |
| 2. Distributed key ceremony | Generate the ElGamal secret jointly so no administrator ever knows the full key; verified trustee custody and recovery plan | Independent ceremony record; no single-key setup used |
| 3. Protocol and implementation review | Review client encryption, proof transcripts, Semaphore integration, serialization, nullifiers, random generation and failure behavior | Independent cryptographic audit and published test vectors |
| 4. Database and API verification | Apply migrations to the target Supabase project; verify RLS, RPC privileges, race behavior, transaction rollback and restore procedures against PostgreSQL | Live integration tests and access-control review pass |
| 5. Contract/deployment design | Deploy immutable election contract, secure authority keys, decide on censorship/recovery, make on-chain and database inclusion records reconcile | Reproducible deployment; audit of attestor and contract; data-availability/gas review |
| 6. Public tally settlement | Add concrete `ITallyProofVerifier`, tie tally to the exact on-chain accepted-ballot commitment, and publish trustee proofs and result | Independent verifier agrees with chain state and published result |
| 7. Operations | Penetration review, load and outage plans, monitoring, key custody, accessible voter journey, incident response and rehearsals | Election authority and independent assessors sign off |

## Known gaps and risks

1. **Eligibility assurance:** control of a university mailbox does not prove current enrollment. The registrar must check an authoritative roster and provide an appeal route.
2. **Enrollment correlation:** issuance flags and commitments have no shared voter key or timestamps, the legacy direct mapping is removed, and group order is shuffled at freeze. The registration server still sees a voter ID and commitment together briefly while processing enrollment; this is not blind credential issuance. Old backups can retain the pre-migration mapping, timestamps and order.
3. **Small anonymity sets:** three Semaphore members satisfy a technical minimum only. The university must enroll a large, legitimate eligible set and document the privacy implications.
4. **Trusted attestor:** the contract relies on one verification authority. That key can censor or attest invalid ballots if the server is compromised. This design is not trustless.
5. **Threshold setup:** current Shamir shares are split from a pre-existing single-admin secret. The original administrator knows the secret, so demo shares do not offer production threshold custody.
6. **Separate log commitments:** the database SHA-256 chain and contract Keccak chain are different. A concrete inclusion/reconciliation proof must bind the exact tally to the exact on-chain ballots.
7. **Tally settlement:** a public script checks the tally and share proofs, but the contract has no concrete tally verifier. The contract's tally publication method is not yet usable as a verified settlement path.
8. **Metadata and coercion:** network/timing metadata remains visible to services and relayers. Remote voting cannot guarantee a private device or prevent coercion.
9. **Audit integrity:** a local hash chain detects modifications to retained rows, but independent checkpoints are needed to detect tail truncation.

## Out of scope

- A production election or real voter records
- A claim that blockchain alone provides anonymity, eligibility, coercion resistance, availability, or correct results
- Production key management, an independently generated threshold key, or administrator MFA
- Placeholder or mock proof verifiers
