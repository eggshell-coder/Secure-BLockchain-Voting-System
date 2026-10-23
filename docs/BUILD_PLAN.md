# Build plan and completion gates

## Prototype delivered in this repository

- Voter-facing election list and registration flow. The development-only OTP is displayed on screen; production registration is unavailable until a delivery provider is configured.
- Administrator sign-in, pending voter review, election draft creation, manifest freeze on publish, and HMAC-linked local audit log.
- A browser check that recomputes each election manifest hash from the API response.
- A same-origin Node API with SQLite persistence, request limits, input bounds, session cookies, security headers, and stable local development secrets.
- A Solidity ballot-box boundary that accepts encrypted ballot bytes and delegates proof checks to configured verifier contracts.
- A threat model and an explicit list of cryptographic components that are not implemented.

**Voting is intentionally disabled.** The user interface and API do not accept a candidate selection or claim a proof passed. The demo election and OTP are not real election records or identity evidence.

The local SQLite registry does not encrypt voter identity fields at rest. Keep the database and local secret file on a trusted development machine and use fictional voter information.

## Work breakdown before any real deployment

| Phase | Deliverables | Completion gate |
| --- | --- | --- |
| 1. Requirements and governance | Election rules, eligibility source, appeal process, privacy retention, accessibility and incident procedures | Election authority approves a written protocol and role separation |
| 2. Credential issuance | One-per-eligible-voter anonymous credential; revocation and recovery design; no identity-to-commitment map | Independent protocol review and privacy analysis |
| 3. Ballot client | Reviewed randomized encryption, manifest-bound ballot validity proof, reproducible client build | Audited cryptographic implementation and misuse-focused review |
| 4. Proof verifiers | Version-pinned on-chain verifier for eligibility and ballot validity | Independent vectors, verifier audit, and gas/DoS analysis |
| 5. Election deployment | Threshold key ceremony, voter group root, frozen manifest, contract verification, relayer policy | Reproducible deployment and published configuration record |
| 6. Tally and verification | Threshold aggregation/decryption, verifiable shares, public tally proof and independent verifier | Independent recomputation agrees with published result |
| 7. Operational readiness | Penetration review, load and outage plans, monitoring, key custody, accessibility review, incident response | Election authority and independent assessors sign off |

## Priority gaps

1. **Identity assurance:** OTP shows control of a contact channel; it does not prove eligibility. The roster and registrar process need a documented source of truth and an appeal path.
2. **Credential privacy:** The issuer must not learn the anonymous membership secret or retain a mapping that links a voter to a nullifier.
3. **Ballot secrecy and validity:** A candidate identifier must never be sent in plaintext. The client must encrypt the choice and prove it encodes exactly one option from the frozen manifest.
4. **Metadata and coercion:** Relaying can still reveal timing and network metadata. Remote voting cannot guarantee a private environment or prevent coercion.
5. **Trustee collusion:** Threshold decryption protects ballots only while fewer than the threshold number of trustees collude and key material remains safe.
6. **Public verifiability:** Voters need inclusion evidence and an independently checkable tally proof, with a procedure for disputes and a fallback if the chain or relayer is unavailable.
7. **Audit integrity:** The prototype log is locally HMAC-linked. Production needs independently witnessed, append-only records and separation between election administrators and audit operators.

## Out of scope for this prototype

- A deployable production election, real voter records, real OTP delivery, or production key management
- A claim that blockchain alone guarantees anonymity, eligibility, coercion resistance, availability, or correct results
- Placeholder or mock proof verifiers
