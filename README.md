# Privacy-Preserving E-Voting Prototype

An educational prototype for a single-organization election. The application provides an administrator console, voter registration and OTP demonstration flow, a frozen election manifest, and a Solidity contract boundary for encrypted ballots.

## Security status

**This project is not ready for a real election.** Ballot submission is deliberately disabled until real, reviewed anonymous-credential, ballot-encryption, eligibility-proof, and tally-proof components are connected. The UI and API do not simulate successful cryptographic verification. The Solidity contract accepts only proofs verified by explicitly supplied verifier contracts.

The API stores voter identity data in Supabase Postgres off-chain and never stores vote choices. The service key is used only by the Node server; it must never be placed in browser code or committed. Use fictional data while evaluating this prototype. The ballot contract records an election-scoped nullifier and a commitment to ciphertext. Do not put a plaintext candidate ID in a message, event, API log, database row, or transaction.

## Requirements

- Node.js 22.13 or newer
- npm

## Run locally

1. For a new Supabase project, apply the SQL files in `supabase/migrations/` in timestamp order. The project configured for this workspace already has these migrations applied; do not paste them into it again.
2. Copy `.env.example` to `.env`, then set `SUPABASE_URL` and a server-only `SUPABASE_SECRET_KEY` (or the legacy `SUPABASE_SERVICE_ROLE_KEY`). Keep both keys out of frontend code and Git.
3. Set `ADMIN_EMAIL` and `ADMIN_PASSWORD`; use a strong password even in development.
4. Install packages with `npm install`.
5. Start the app with `npm start`. Startup checks the server-to-Supabase connection.
6. Open `http://localhost:4173`.
7. OTP is shown in development only. No email or SMS provider is configured. Expired or locked-out demo codes can be reissued while the registration is still pending.

The first startup creates stable local-only JWT and OTP secrets if they are not configured. Voter registrations, verification challenges, elections, candidates, and the audit chain are stored in Supabase Postgres. No fictional election is automatically inserted.

## Contracts

`contracts/SecureElection.sol` is an immutable election contract with verifier interfaces. It contains no mock verifier and no plaintext vote count. Install dependencies with `npm install`, then compile with `npm run compile:contracts`.

Before enabling voting, implement and independently review the verifier contracts and client-side cryptography. The required ballot-validity proof must bind the encrypted ballot to the frozen manifest and prove exactly one valid selection. The tally verifier must prove its result corresponds to the accepted encrypted-ballot record.

## Project structure

```text
public/       voter, administrator, and verification UI
server/       same-origin API, Supabase Postgres access, OTP demo, audit chain
supabase/     normalized SQL migrations and atomic server-side RPC functions
contracts/    immutable encrypted-ballot contract and verifier interfaces
docs/         threat model and cryptographic integration boundary
```

See [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md) for the implemented scope and remaining work before a real election can be considered.

## Important limitations

- OTP proves control of a channel, not eligibility. Eligibility depends on the organization’s roster and registrar process.
- A relayer does not automatically hide IP address, timing, or service-side metadata.
- Remote voting cannot guarantee a private voting environment or coercion resistance.
- Testnet deployment does not establish production security or availability.
- The database audit chain is append-only for the application role and detects changes to retained events; independent checkpoints are still needed to detect tail truncation.
- The prototype has one environment-configured administrator account and no MFA or production identity provider.
- The server-side Supabase key is privileged. Rotate it if it has been shared or exposed, and do not deploy the demo OTP flow to production.
