# Privacy-Preserving E-Voting Prototype

An educational prototype for a single-organization election. The application provides an administrator console, voter registration and OTP demonstration flow, a frozen election manifest, and a Solidity contract boundary for encrypted ballots.

## Security status

**This project is not ready for a real election.** Ballot submission is deliberately disabled until real, reviewed anonymous-credential, ballot-encryption, eligibility-proof, and tally-proof components are connected. The UI and API do not simulate successful cryptographic verification. The Solidity contract accepts only proofs verified by explicitly supplied verifier contracts.

The API stores voter identity data off-chain and never stores vote choices. In this prototype, identity fields are stored in local SQLite without application-level encryption at rest; use fictional data only. The ballot contract records an election-scoped nullifier and a commitment to ciphertext. Do not put a plaintext candidate ID in a message, event, API log, database row, or transaction.

## Requirements

- Node.js 22.13 or newer
- npm

## Run locally

1. Copy `.env.example` to `.env` and set local-only secrets.
2. Install packages with `npm install`.
3. Start the app with `npm start`.
4. Open `http://localhost:4173`.
5. In development, the demo administrator is `admin@demo.local`; the example environment file sets its password to `change-this-local-password`. Without a `.env` file, the local fallback password is `change-me-now`. Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` before the first startup because the account is seeded once.
6. OTP is shown in the local development response only. No email or SMS provider is configured. Expired or locked-out demo codes can be reissued while the registration is still pending.

The first startup creates `data/voting.sqlite`, stable local-only secrets, and a fictional sample election. The database, local secrets, and voter records are excluded from version control.

## Contracts

`contracts/SecureElection.sol` is an immutable election contract with verifier interfaces. It contains no mock verifier and no plaintext vote count. Install dependencies with `npm install`, then compile with `npm run compile:contracts`.

Before enabling voting, implement and independently review the verifier contracts and client-side cryptography. The required ballot-validity proof must bind the encrypted ballot to the frozen manifest and prove exactly one valid selection. The tally verifier must prove its result corresponds to the accepted encrypted-ballot record.

## Project structure

```text
public/       voter, administrator, and verification UI
server/       same-origin API, SQLite registry, OTP demo, audit chain
contracts/    immutable encrypted-ballot contract and verifier interfaces
docs/         threat model and cryptographic integration boundary
```

See [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md) for the implemented scope and remaining work before a real election can be considered.

## Important limitations

- OTP proves control of a channel, not eligibility. Eligibility depends on the organization’s roster and registrar process.
- A relayer does not automatically hide IP address, timing, or service-side metadata.
- Remote voting cannot guarantee a private voting environment or coercion resistance.
- Testnet deployment does not establish production security or availability.
- The local SQLite audit chain can detect edits to retained rows when the audit secret is intact, but cannot detect tail truncation without an external checkpoint and is not an independent WORM audit system.
- The prototype has one seeded administrator account and no MFA or production identity provider.
