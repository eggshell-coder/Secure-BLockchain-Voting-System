-- Initial normalized schema for the Secure Blockchain Voting System.
-- The database stores voter eligibility and public election metadata. It never
-- stores a plaintext ballot or a voter-to-ballot relationship.

CREATE TABLE public.voters (
  voter_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  full_name text NOT NULL,
  email text NOT NULL,
  email_verified_at timestamptz,
  registration_status text NOT NULL DEFAULT 'pending',
  registration_reviewed_at timestamptz,
  registration_reviewed_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT voters_organization_id_nonempty CHECK (
    organization_id = btrim(organization_id)
    AND char_length(organization_id) BETWEEN 3 AND 80
  ),
  CONSTRAINT voters_full_name_nonempty CHECK (
    full_name = btrim(full_name)
    AND char_length(full_name) BETWEEN 2 AND 120
  ),
  CONSTRAINT voters_email_nonempty CHECK (
    email = lower(btrim(email))
    AND char_length(email) BETWEEN 3 AND 254
  ),
  CONSTRAINT voters_registration_status_check CHECK (
    registration_status IN ('pending', 'approved', 'rejected')
  ),
  CONSTRAINT voters_registration_review_check CHECK (
    (registration_status = 'pending' AND registration_reviewed_at IS NULL)
    OR (registration_status IN ('approved', 'rejected') AND registration_reviewed_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX voters_organization_id_uq
  ON public.voters (lower(organization_id));
CREATE INDEX voters_email_idx ON public.voters (email);

COMMENT ON COLUMN public.voters.organization_id IS
  'The individual voter identifier used by the existing application, not an organization table key.';

CREATE TABLE public.verification_challenges (
  challenge_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  voter_id uuid NOT NULL REFERENCES public.voters(voter_id) ON DELETE CASCADE,
  purpose text NOT NULL DEFAULT 'email_verification',
  secret_hash bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  attempt_count smallint NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  consumed_at timestamptz,
  CONSTRAINT verification_challenge_purpose_check CHECK (purpose = 'email_verification'),
  CONSTRAINT verification_challenge_hash_length CHECK (octet_length(secret_hash) = 32),
  CONSTRAINT verification_challenge_attempts_check CHECK (attempt_count BETWEEN 0 AND 5),
  CONSTRAINT verification_challenge_status_check CHECK (
    status IN ('active', 'consumed', 'locked', 'superseded', 'expired')
  ),
  CONSTRAINT verification_challenge_consumed_check CHECK (
    (status = 'consumed') = (consumed_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX verification_one_active_challenge_per_voter
  ON public.verification_challenges (voter_id, purpose)
  WHERE status = 'active';
CREATE INDEX verification_challenges_expiry_idx
  ON public.verification_challenges (expires_at)
  WHERE status = 'active';

CREATE TABLE public.app_roles (
  role_code text PRIMARY KEY,
  description text NOT NULL,
  CONSTRAINT app_roles_code_nonempty CHECK (role_code = lower(btrim(role_code)) AND role_code <> '')
);

INSERT INTO public.app_roles (role_code, description) VALUES
  ('election_admin', 'Manage election configuration and publication.'),
  ('eligibility_reviewer', 'Review voter registration and election eligibility.'),
  ('auditor', 'Read and verify the append-only administrative audit trail.'),
  ('trustee', 'Participate in the election decryption and tally protocol.')
ON CONFLICT (role_code) DO NOTHING;

CREATE TABLE public.user_roles (
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role_code text NOT NULL REFERENCES public.app_roles(role_code) ON DELETE RESTRICT,
  granted_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_code)
);

CREATE TABLE public.elections (
  election_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  manifest_hash bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT elections_title_check CHECK (
    title = btrim(title) AND char_length(title) BETWEEN 3 AND 200
  ),
  CONSTRAINT elections_description_check CHECK (char_length(description) <= 10000),
  CONSTRAINT elections_time_window_check CHECK (starts_at < ends_at),
  CONSTRAINT elections_status_check CHECK (
    status IN ('draft', 'scheduled', 'active', 'closed', 'certified', 'cancelled')
  ),
  CONSTRAINT elections_manifest_hash_length CHECK (
    manifest_hash IS NULL OR octet_length(manifest_hash) = 32
  )
);

CREATE INDEX elections_public_schedule_idx
  ON public.elections (starts_at, ends_at)
  WHERE status <> 'draft';

CREATE TABLE public.candidates (
  candidate_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  election_id uuid NOT NULL REFERENCES public.elections(election_id) ON DELETE CASCADE,
  display_name text NOT NULL,
  manifesto text NOT NULL DEFAULT '',
  list_order smallint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT candidates_name_check CHECK (
    display_name = btrim(display_name) AND char_length(display_name) BETWEEN 2 AND 100
  ),
  CONSTRAINT candidates_manifesto_check CHECK (char_length(manifesto) <= 1000),
  CONSTRAINT candidates_list_order_check CHECK (list_order BETWEEN 1 AND 20),
  CONSTRAINT candidates_election_order_uq UNIQUE (election_id, list_order),
  CONSTRAINT candidates_election_id_uq UNIQUE (election_id, candidate_id)
);

CREATE INDEX candidates_election_idx ON public.candidates (election_id, list_order);

CREATE TABLE public.election_voters (
  election_id uuid NOT NULL REFERENCES public.elections(election_id) ON DELETE CASCADE,
  voter_id uuid NOT NULL REFERENCES public.voters(voter_id) ON DELETE CASCADE,
  eligibility_status text NOT NULL DEFAULT 'pending',
  reviewed_at timestamptz,
  reviewed_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  eligibility_commitment bytea,
  credential_issued_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (election_id, voter_id),
  CONSTRAINT election_voters_status_check CHECK (
    eligibility_status IN ('pending', 'approved', 'rejected', 'revoked')
  ),
  CONSTRAINT election_voters_review_check CHECK (
    (eligibility_status = 'pending' AND reviewed_at IS NULL)
    OR (eligibility_status <> 'pending' AND reviewed_at IS NOT NULL)
  ),
  CONSTRAINT election_voters_commitment_length CHECK (
    eligibility_commitment IS NULL OR octet_length(eligibility_commitment) = 32
  ),
  CONSTRAINT election_voters_credential_check CHECK (
    credential_issued_at IS NULL
    OR (eligibility_status = 'approved' AND eligibility_commitment IS NOT NULL)
  )
);

CREATE UNIQUE INDEX election_voters_commitment_uq
  ON public.election_voters (election_id, eligibility_commitment)
  WHERE eligibility_commitment IS NOT NULL;
CREATE INDEX election_voters_voter_idx ON public.election_voters (voter_id, election_id);

CREATE TABLE public.election_chain_deployments (
  deployment_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  election_id uuid NOT NULL REFERENCES public.elections(election_id) ON DELETE RESTRICT,
  chain_id numeric(78, 0) NOT NULL,
  contract_address bytea NOT NULL,
  deployment_tx_hash bytea NOT NULL,
  deployment_block_number numeric(78, 0) NOT NULL,
  voter_group_root bytea NOT NULL,
  election_public_key_hash bytea NOT NULL,
  deployed_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT deployments_chain_id_check CHECK (chain_id > 0),
  CONSTRAINT deployments_contract_address_length CHECK (octet_length(contract_address) = 20),
  CONSTRAINT deployments_tx_hash_length CHECK (octet_length(deployment_tx_hash) = 32),
  CONSTRAINT deployments_block_number_check CHECK (deployment_block_number >= 0),
  CONSTRAINT deployments_group_root_length CHECK (octet_length(voter_group_root) = 32),
  CONSTRAINT deployments_public_key_hash_length CHECK (octet_length(election_public_key_hash) = 32),
  CONSTRAINT deployments_election_chain_uq UNIQUE (election_id, chain_id),
  CONSTRAINT deployments_chain_address_uq UNIQUE (chain_id, contract_address)
);

CREATE TABLE public.chain_ballot_events (
  election_id uuid NOT NULL,
  chain_id numeric(78, 0) NOT NULL,
  transaction_hash bytea NOT NULL,
  log_index integer NOT NULL,
  block_number numeric(78, 0) NOT NULL,
  nullifier bytea NOT NULL,
  ballot_hash bytea NOT NULL,
  indexed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, transaction_hash, log_index),
  CONSTRAINT chain_ballot_deployment_fk FOREIGN KEY (election_id, chain_id)
    REFERENCES public.election_chain_deployments(election_id, chain_id) ON DELETE RESTRICT,
  CONSTRAINT chain_ballot_tx_hash_length CHECK (octet_length(transaction_hash) = 32),
  CONSTRAINT chain_ballot_log_index_check CHECK (log_index >= 0),
  CONSTRAINT chain_ballot_block_number_check CHECK (block_number >= 0),
  CONSTRAINT chain_ballot_nullifier_length CHECK (octet_length(nullifier) = 32),
  CONSTRAINT chain_ballot_hash_length CHECK (octet_length(ballot_hash) = 32),
  CONSTRAINT chain_ballot_one_nullifier_per_deployment UNIQUE (election_id, chain_id, nullifier)
);

CREATE INDEX chain_ballot_events_election_block_idx
  ON public.chain_ballot_events (election_id, block_number, log_index);

CREATE TABLE public.published_tallies (
  election_id uuid NOT NULL,
  chain_id numeric(78, 0) NOT NULL,
  transaction_hash bytea NOT NULL,
  block_number numeric(78, 0) NOT NULL,
  accepted_ballots_hash bytea NOT NULL,
  result_hash bytea NOT NULL,
  tally_proof_hash bytea NOT NULL,
  finalized_at timestamptz NOT NULL,
  PRIMARY KEY (election_id, chain_id),
  CONSTRAINT tallies_deployment_fk FOREIGN KEY (election_id, chain_id)
    REFERENCES public.election_chain_deployments(election_id, chain_id) ON DELETE RESTRICT,
  CONSTRAINT tallies_tx_hash_length CHECK (octet_length(transaction_hash) = 32),
  CONSTRAINT tallies_block_number_check CHECK (block_number >= 0),
  CONSTRAINT tallies_ballots_hash_length CHECK (octet_length(accepted_ballots_hash) = 32),
  CONSTRAINT tallies_result_hash_length CHECK (octet_length(result_hash) = 32),
  CONSTRAINT tallies_proof_hash_length CHECK (octet_length(tally_proof_hash) = 32),
  CONSTRAINT tallies_chain_tx_uq UNIQUE (chain_id, transaction_hash)
);

CREATE TABLE public.candidate_results (
  election_id uuid NOT NULL,
  chain_id numeric(78, 0) NOT NULL,
  candidate_id uuid NOT NULL,
  vote_count bigint NOT NULL,
  PRIMARY KEY (election_id, chain_id, candidate_id),
  CONSTRAINT candidate_results_count_check CHECK (vote_count >= 0),
  CONSTRAINT candidate_results_tally_fk FOREIGN KEY (election_id, chain_id)
    REFERENCES public.published_tallies(election_id, chain_id) ON DELETE RESTRICT,
  CONSTRAINT candidate_results_candidate_fk FOREIGN KEY (election_id, candidate_id)
    REFERENCES public.candidates(election_id, candidate_id) ON DELETE RESTRICT
);

CREATE TABLE public.audit_action_types (
  action_code text PRIMARY KEY,
  description text NOT NULL,
  CONSTRAINT audit_action_code_check CHECK (
    action_code = lower(btrim(action_code)) AND action_code <> ''
  )
);

INSERT INTO public.audit_action_types (action_code, description) VALUES
  ('voter.registered', 'A voter registration was created.'),
  ('voter.email_verified', 'A voter verified control of the registered email channel.'),
  ('voter.approved', 'A registrar approved a voter registration.'),
  ('voter.rejected', 'A registrar rejected a voter registration.'),
  ('eligibility.approved', 'A voter was approved for an election.'),
  ('eligibility.rejected', 'A voter was rejected for an election.'),
  ('eligibility.revoked', 'Election eligibility was revoked.'),
  ('election.created', 'An election draft was created.'),
  ('election.updated', 'An election draft was updated.'),
  ('election.published', 'An election manifest was published.'),
  ('election.cancelled', 'An election was cancelled.'),
  ('chain.deployed', 'An election contract deployment was recorded.'),
  ('tally.published', 'A verified election tally was published.'),
  ('role.granted', 'An application role was granted.'),
  ('role.revoked', 'An application role was revoked.')
ON CONFLICT (action_code) DO NOTHING;

CREATE TABLE public.audit_chain_head (
  head_id boolean PRIMARY KEY DEFAULT true CHECK (head_id),
  last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
  last_hash bytea NOT NULL,
  CONSTRAINT audit_chain_head_hash_length CHECK (octet_length(last_hash) = 32)
);

INSERT INTO public.audit_chain_head (head_id, last_sequence, last_hash)
VALUES (true, 0, decode(repeat('00', 32), 'hex'));

CREATE TABLE public.audit_events (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_sequence bigint NOT NULL UNIQUE,
  actor_kind text NOT NULL,
  actor_user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  action_code text NOT NULL REFERENCES public.audit_action_types(action_code) ON DELETE RESTRICT,
  subject_voter_id uuid REFERENCES public.voters(voter_id) ON DELETE SET NULL,
  subject_election_id uuid REFERENCES public.elections(election_id) ON DELETE SET NULL,
  subject_candidate_id uuid REFERENCES public.candidates(candidate_id) ON DELETE SET NULL,
  subject_challenge_id uuid REFERENCES public.verification_challenges(challenge_id) ON DELETE SET NULL,
  request_id uuid,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  previous_hash bytea NOT NULL,
  event_hash bytea NOT NULL UNIQUE,
  CONSTRAINT audit_actor_kind_check CHECK (actor_kind IN ('user', 'system', 'indexer')),
  CONSTRAINT audit_actor_identity_check CHECK (
    (actor_kind = 'user') = (actor_user_id IS NOT NULL)
  ),
  CONSTRAINT audit_single_subject_check CHECK (
    num_nonnulls(subject_voter_id, subject_election_id, subject_candidate_id, subject_challenge_id) <= 1
  ),
  CONSTRAINT audit_previous_hash_length CHECK (octet_length(previous_hash) = 32),
  CONSTRAINT audit_event_hash_length CHECK (octet_length(event_hash) = 32)
);

CREATE INDEX audit_events_occurred_at_idx ON public.audit_events (occurred_at DESC);
CREATE INDEX audit_events_voter_idx ON public.audit_events (subject_voter_id, event_sequence DESC)
  WHERE subject_voter_id IS NOT NULL;
CREATE INDEX audit_events_election_idx ON public.audit_events (subject_election_id, event_sequence DESC)
  WHERE subject_election_id IS NOT NULL;

CREATE OR REPLACE FUNCTION public.audit_events_chain_before_insert()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
  current_sequence bigint;
  current_hash bytea;
  event_payload text;
BEGIN
  SELECT last_sequence, last_hash
    INTO current_sequence, current_hash
    FROM public.audit_chain_head
    WHERE head_id = true
    FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Audit chain head is missing';
  END IF;

  NEW.event_sequence := current_sequence + 1;
  NEW.occurred_at := COALESCE(NEW.occurred_at, pg_catalog.clock_timestamp());
  NEW.previous_hash := current_hash;
  event_payload := pg_catalog.jsonb_build_object(
    'event_sequence', NEW.event_sequence,
    'actor_kind', NEW.actor_kind,
    'actor_user_id', NEW.actor_user_id,
    'action_code', NEW.action_code,
    'subject_voter_id', NEW.subject_voter_id,
    'subject_election_id', NEW.subject_election_id,
    'subject_candidate_id', NEW.subject_candidate_id,
    'subject_challenge_id', NEW.subject_challenge_id,
    'request_id', NEW.request_id,
    'occurred_at_utc', pg_catalog.to_char(
      NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'
    ),
    'previous_hash', pg_catalog.encode(NEW.previous_hash, 'hex')
  )::text;
  NEW.event_hash := extensions.digest(pg_catalog.convert_to(event_payload, 'UTF8'), 'sha256');

  UPDATE public.audit_chain_head
    SET last_sequence = NEW.event_sequence,
        last_hash = NEW.event_hash
    WHERE head_id = true;

  RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION public.audit_events_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $function$
BEGIN
  RAISE EXCEPTION 'Audit events are append-only';
END;
$function$;

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $function$
BEGIN
  NEW.updated_at := pg_catalog.clock_timestamp();
  RETURN NEW;
END;
$function$;

CREATE TRIGGER voters_set_updated_at
  BEFORE UPDATE ON public.voters
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER elections_set_updated_at
  BEFORE UPDATE ON public.elections
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER election_voters_set_updated_at
  BEFORE UPDATE ON public.election_voters
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER audit_events_chain_before_insert
  BEFORE INSERT ON public.audit_events
  FOR EACH ROW EXECUTE FUNCTION public.audit_events_chain_before_insert();

CREATE TRIGGER audit_events_no_update_or_delete
  BEFORE UPDATE OR DELETE ON public.audit_events
  FOR EACH ROW EXECUTE FUNCTION public.audit_events_reject_mutation();

CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON public.audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION public.audit_events_reject_mutation();

ALTER TABLE public.voters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.verification_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.elections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.election_voters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.election_chain_deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chain_ballot_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.published_tallies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.candidate_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_action_types ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_chain_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE
  public.voters,
  public.verification_challenges,
  public.app_roles,
  public.user_roles,
  public.elections,
  public.candidates,
  public.election_voters,
  public.election_chain_deployments,
  public.chain_ballot_events,
  public.published_tallies,
  public.candidate_results,
  public.audit_action_types,
  public.audit_chain_head,
  public.audit_events
FROM anon, authenticated;

GRANT SELECT ON TABLE public.elections, public.candidates TO anon, authenticated;

CREATE POLICY published_elections_are_readable
  ON public.elections
  FOR SELECT
  TO anon, authenticated
  USING (status <> 'draft');

CREATE POLICY published_candidates_are_readable
  ON public.candidates
  FOR SELECT
  TO anon, authenticated
  USING (
    EXISTS (
      SELECT 1
      FROM public.elections AS e
      WHERE e.election_id = candidates.election_id
        AND e.status <> 'draft'
    )
  );

GRANT USAGE ON SCHEMA public TO service_role;
GRANT ALL PRIVILEGES ON TABLE
  public.voters,
  public.verification_challenges,
  public.app_roles,
  public.user_roles,
  public.elections,
  public.candidates,
  public.election_voters,
  public.election_chain_deployments,
  public.chain_ballot_events,
  public.published_tallies,
  public.candidate_results,
  public.audit_action_types
TO service_role;
GRANT SELECT, INSERT ON TABLE public.audit_events TO service_role;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.audit_events FROM service_role;
GRANT USAGE, SELECT ON SEQUENCE public.audit_events_event_id_seq TO service_role;

REVOKE ALL ON FUNCTION public.audit_events_chain_before_insert() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.audit_events_reject_mutation() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.set_updated_at() FROM PUBLIC, anon, authenticated, service_role;

COMMENT ON TABLE public.election_voters IS
  'Private eligibility mapping; never join this table to chain_ballot_events or expose it through public APIs.';
COMMENT ON TABLE public.chain_ballot_events IS
  'Indexer cache of public chain events. Stores no voter ID, candidate choice, or plaintext ballot.';
COMMENT ON TABLE public.candidate_results IS
  'Post-election aggregate totals only; populate only after the tally proof is verified.';
COMMENT ON TABLE public.audit_events IS
  'Append-only, transactionally serialized SHA-256 audit chain for administrative and system events.';
