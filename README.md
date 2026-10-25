# Privacy-Preserving E-Voting Prototype

An educational prototype for a single-organization election. It provides a university-account registration flow, registrar review, an administrator console, frozen election manifests, and a Solidity boundary for encrypted ballots.

## Security status

**This project is not ready for a real election.** The repository now contains prototype browser encryption, ballot and Semaphore proof verification, hash-chained ballot storage, an attested Solidity relay, 2-of-3 tally helpers, a public export and verifier. These components are not independently audited or deployed end to end. Ballot submission remains disabled in both the API and UI; the code does not simulate successful ballot acceptance.

The API stores voter identity data in Supabase Postgres off-chain and never stores vote choices. Voters register with a name, university email, and password, confirm the email through Supabase Auth, then sign in with email and password. The browser uses only the publishable key, while the server requires a confirmed email and an approved university email domain. The server-only secret key must never be placed in browser code or committed. A university email domain proves control of that account, not current enrollment; a registrar must verify the submitted student ID against the university roster. Use fictional data while evaluating this prototype. The ballot contract records an election-scoped nullifier and a commitment to ciphertext. Do not put a plaintext candidate ID in a message, event, API log, database row, or transaction.

## Requirements

- Node.js 22.13 or newer
- npm

## Run locally

1. Apply the SQL files in `supabase/migrations/` in timestamp order to your Supabase project. The migrations are present in this repository; this workspace has not applied them to your remote database.
2. Copy `.env.example` to `.env`, then set `SUPABASE_URL`, the browser-safe `SUPABASE_PUBLISHABLE_KEY`, `VOTER_EMAIL_DOMAINS`, and a server-only `SUPABASE_SECRET_KEY` (or the legacy `SUPABASE_SERVICE_ROLE_KEY`). Keep the server key out of frontend code and Git.
3. Set `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD`.
4. Install packages with `npm install`.
5. In Supabase Auth, enable the Email provider and turn on **Confirm email**. For local development set Site URL to `http://localhost:4173` and add `http://localhost:4173/**` plus your production app URL to the redirect URL allowlist. Use the Supabase signup confirmation link template (`{{ .ConfirmationURL }}`). Configure custom SMTP with a verified sender if confirmation emails must reach users outside your Supabase organization team.
6. Start the app with `npm start`. It bundles the browser Auth client and checks the server-to-Supabase connection.
7. Open `http://localhost:4173`.

The first startup creates a stable local-only JWT secret if none is configured. Voter registrations, Supabase Auth identity links, elections, candidates, and the audit chain are stored in Supabase Postgres. No fictional election is automatically inserted.

## Prototype election key setup

Create a draft election and candidates in the admin panel. While the app is running, copy the draft election UUID and run:

```powershell
npm run election:keygen -- <draft-election-uuid>
```

The script signs in with the local `ADMIN_EMAIL` and `ADMIN_PASSWORD`, refuses if the election already has a key, saves the single prototype secret key under `data/election-keys/`, and sends only the public key to the server/database. On success it prints only the SHA-256 fingerprint of the public key. The public key becomes part of the frozen election manifest, so generate it before publishing. The private key is not encrypted by this prototype; protect the local file and any backups. Its directory is explicitly ignored by Git.

This single-admin key is for local demonstrations only. It does not provide trustee separation. Existing published elections created before this migration keep their old manifest and have no election key; the client will refuse to encrypt for them.

For a legacy scheduled election that has no key, use `npm run election:reopen-keygen -- <election-uuid>`. This admin-only command returns the election to draft, clears its old manifest hash, and then runs the ordinary key generator. The database refuses the transition if the election has started, already has a key, has ballots or voter identity enrollments, has a frozen Semaphore group, or has a contract deployment or tally. The command leaves the election in draft; an administrator must publish it again so the public manifest commits to the new key. It is safe to rerun after a partial failure while the election remains an unkeyed draft.

After the registrar approves a voter, the voter portal can create an election-specific Semaphore identity before registration closes. The browser protects the private identity with a recovery passphrase and submits the public commitment into a timestamp-free pending table. At freeze, the server shuffles commitments before inserting them into the public group. The registration server briefly sees the authenticated user ID and commitment together; this is not blind issuance. Keep the recovery passphrase safe: the server cannot restore the identity.

## Public ballot export and verifier

The API exposes public encrypted ballots, anonymous Semaphore proofs, group commitments, and the database hash-chain head for each published election. Export after the API and Supabase migrations are configured:

```powershell
npm run election:export -- <election-uuid>
```

The 2-of-3 split and tally commands below are prototype demonstrations. The split begins with an administrator-generated single key and is not an independent key ceremony:

```powershell
npm run election:split-key -- <election-uuid>
npm run election:tally -- public-election-<election-uuid>.json data/election-keys/<election-uuid>-trustees-2-of-3/trustee-1.json data/election-keys/<election-uuid>-trustees-2-of-3/trustee-2.json
npm run election:verify -- public-election-<election-uuid>.json tally-<election-uuid>.json
```

Anyone with the exported dataset and published tally can run the verifier. It needs no trustee secret shares.

## Contracts

`contracts/SecureElection.sol` is an immutable election contract with verifier interfaces. It contains no mock verifier and no plaintext vote count. Install dependencies with `npm install`, then compile with `npm run compile:contracts`.

The contract relays encrypted ballot bytes only when the configured verification authority signs an EIP-712 attestation bound to election, manifest, group root, scope, nullifier and ballot hash. The attestor is trusted because the contract does not verify the Ristretto/Semaphore proofs itself. `ITallyProofVerifier` is an interface only; no concrete on-chain verifier is included. Do not deploy this as trustless voting.

## Project structure

```text
public/       voter, administrator, and verification UI
server/       same-origin API, Supabase Postgres/Auth verification, audit chain
supabase/     normalized SQL migrations and atomic server-side RPC functions
contracts/    immutable encrypted-ballot contract and verifier interfaces
docs/         threat model and cryptographic integration boundary
```

See [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md) for the implemented scope and remaining work before a real election can be considered.

## Important limitations

- Email confirmation and an allowed email domain prove control of a university mailbox, not active enrollment. Eligibility depends on the organization’s roster and registrar process.
- A relayer does not automatically hide IP address, timing, or service-side metadata.
- Remote voting cannot guarantee a private voting environment or coercion resistance.
- Testnet deployment does not establish production security or availability.
- The database audit chain is append-only for the application role and detects changes to retained events; independent checkpoints are still needed to detect tail truncation.
- The prototype has one environment-configured administrator account and no administrator MFA.
- The server-side Supabase key is privileged. Rotate it if it has been shared or exposed. Email sign-in requires the Supabase Email provider, Confirm email, and an allowed confirmation redirect URL.
