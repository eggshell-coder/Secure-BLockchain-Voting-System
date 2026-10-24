# Cryptographic implementation and trust boundary

## Implemented prototype flow

1. **Election key:** a draft election can receive a Ristretto255 ElGamal public key using `npm run election:keygen -- <election-uuid>`. Supabase stores the public key and `prototype_single_key` status. The secret is saved locally under ignored `data/election-keys/`. The key is part of the published manifest. The client refuses to encrypt without it.
   A legacy scheduled election with no key can use `npm run election:reopen-keygen -- <election-uuid>`. A database guard allows this only before the scheduled start and only if no key, ballot, Semaphore enrollment/group, contract deployment, or tally exists. It clears the old manifest hash and leaves the election in draft; an administrator must republish it to publish a manifest containing the key.
2. **Encrypted ballot and validity:** the browser encrypts a one-hot candidate vector using exponential ElGamal and creates a disjunctive Chaum-Pedersen proof for each bit plus a sum-equals-one proof. The server verifier checks canonical Ristretto encodings, rejects identity ballot points, binds election ID, manifest, candidate order, key and ballot ID, and checks the election window.
3. **Eligibility:** the browser holds a passphrase-encrypted Semaphore V4 identity. After verified Supabase authentication and registrar approval, the API stages only the commitment in a timestamp-free pending table. When registration closes, `freeze_semaphore_group` validates the pending set and inserts it in CSPRNG-shuffled order; only then are group commitments published. The voter issuance table has no timestamp or commitment, and group members have no timestamp or voter ID. The migration also removes legacy voter-to-commitment columns from `election_voters`. Semaphore proofs bind the ballot digest as signal and election UUID as scope; the server checks the frozen group root and proof. A unique `(election_id, nullifier)` constraint prevents concurrent duplicate voting.
4. **Accepted ballot log:** the SQL RPC stores the encrypted ballot and Semaphore proof, nullifier, and a per-election append-only SHA-256 chain record. Each chain record commits to both the ballot digest and canonical Semaphore proof digest. A public endpoint exports the manifest, group commitments, proof artifacts, rows, and chain head. The independent verifier recomputes each ballot proof, Semaphore proof, proof digest, chain record and tally.
5. **Contract relay:** `SecureElection.sol` stores the full encrypted ballot bytes, ballot digest and Semaphore nullifier, and prevents nullifier reuse. Since Solidity does not verify these Ristretto and Semaphore proofs, the contract accepts an EIP-712 attestation from a configured verification authority. This is a trusted-attestor design, not trustless verification. The server relay checks contract configuration before sending.
6. **Threshold tally prototype:** the tally module splits an existing scalar into Shamir 2-of-3 shares, aggregates ciphertexts per candidate, and verifies Chaum-Pedersen proofs for trustee decryption shares before recovering candidate counts. The public verifier recomputes aggregates and checks the shares, counts and result hash.

## Still disabled or incomplete

`POST /api/vote/relay` remains unavailable: `ENABLE_BALLOT_ACCEPTANCE` defaults to false and `cryptoReadiness.votingEnabled` is hard-coded false. There is no voter cast button. The environment flag alone cannot turn voting on. The API, Supabase migrations and contract relay have not been exercised as one deployed end-to-end system in this workspace.

The 2-of-3 split command starts from a key that was first generated and known by one administrator. It demonstrates the math, but does not erase that administrator's knowledge or constitute an independent trustee ceremony. It must not be represented as production threshold custody. A fresh distributed key ceremony is still required before real elections.

There is no concrete deployed on-chain tally verifier implementing `ITallyProofVerifier`; therefore the contract's `publishTally` cannot be treated as an operational result publication path. The tally CLI proves individual trustee shares and computes a result, but it does not create a succinct proof for the current contract interface. The contract's `acceptedBallotsHash` uses a separate on-chain Keccak chain from the database SHA-256 chain; a production reconciliation and inclusion design is still required.

The registration server necessarily sees the authenticated user ID and submitted commitment together briefly while it validates and stores an enrollment. Application logs redact request-specific errors and do not log both values, but this is not blind credential issuance; server compromise or request tracing could still correlate them. Existing backups or database logs created before the privacy migration may retain the old direct mapping, timestamps and ordering. The migration refuses to reset a group whose election has already opened. A minimum group of three does not provide useful anonymity. Semaphore identity recovery depends on the voter's local encrypted vault and passphrase; the server cannot restore it. EVM relay signing and contract deployment also require configuration and independent review.

## Commands

```powershell
npm run election:keygen -- <draft-election-uuid>
npm run election:reopen-keygen -- <scheduled-election-uuid>
npm run election:split-key -- <election-uuid>
npm run election:export -- <election-uuid>
npm run election:tally -- public-election-<election-uuid>.json data/election-keys/<election-uuid>-trustees-2-of-3/trustee-1.json data/election-keys/<election-uuid>-trustees-2-of-3/trustee-2.json
npm run election:verify -- public-election-<election-uuid>.json tally-<election-uuid>.json
npm run test:crypto
npm run compile:contracts
```

The key split script writes demo shares under `data/election-keys/<election-id>-trustees-2-of-3/`; protect those files. The export and tally scripts refuse to overwrite existing output files. The verifier does not need trustee secrets.

## Security limitations

The code is a prototype and has not been independently audited. JavaScript BigInt curve operations are not guaranteed constant-time. The contract trusts one verification authority that can accept, reject or censor ballots. The backend sees IP/timing metadata, and remote voting cannot prevent coercion or compromised client devices. The database chain detects edits to retained records but cannot detect tail truncation without external witnessed checkpoints. Do not use this system for a binding or real election.

The `votingCrypto` browser global exposes encryption and ballot proof helpers; `votingSemaphore` exposes encrypted identity and proof helpers. Keep election private keys, trustee shares, identity secrets and per-ballot randomness out of server requests. Only encrypted ballots and zero-knowledge proof artifacts may be submitted.
