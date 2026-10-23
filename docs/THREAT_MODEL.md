# Threat model

## Assets

- Voter identity and eligibility records
- Anonymous credential secrets
- Encrypted ballot contents and trustee decryption shares
- Frozen election manifest and accepted-ballot record
- Availability of voter, relayer, and verification services

## Adversaries considered

- A voter attempting to submit more than one ballot or an invalid ballot
- A malicious or compromised voter browser
- A registrar or administrator acting alone or colluding with another role
- A relayer that delays, observes, or drops submissions
- An attacker who reads or alters the off-chain voter registry
- A trustee quorum attempting to reveal individual choices
- A public observer correlating on-chain timing and metadata

## Required protections

- Keep personal data and plaintext choices off-chain and out of events.
- Separate eligibility authentication from ballot submission.
- Bind every proof to the election scope and frozen manifest.
- Use unique election-scoped nullifiers and reject duplicates.
- Freeze the voter group root, election dates, manifest, and verifier version.
- Publish enough encrypted artifacts and proof data for independent verification.
- Require a publicly verifiable tally proof before showing final results.
- Record administrator actions in a tamper-evident chain without voter PII.

## Explicitly unmitigated in this prototype

- Voter identity fields in local SQLite are not encrypted at rest; this build is for fictional data only.
- The administrator account is single-factor and seeded locally; there is no production identity provider or multi-role authorization.
- OTP is returned by the local API in development and is not delivered over an independent channel.
- Malware or malicious extensions on the voter's device
- Coercion, vote buying, or observation of a remote voter
- Registrar collusion or an incorrect source roster
- Collusion by enough decryption trustees
- Network censorship, chain congestion, or broad service outages
- Removal of the newest rows from the local audit log without an independently retained head checkpoint

## Trust boundaries

The registrar learns voter identity. The credential issuance protocol must prevent it from learning the identity commitment used in anonymous voting. The ballot client sees the selection before encryption. Trustees can potentially decrypt ballots if their threshold colludes. The relayer sees network metadata even when it does not receive the voter ID. These assumptions must be documented and tested rather than described as trustless.
