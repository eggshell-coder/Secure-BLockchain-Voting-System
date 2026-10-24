ALTER TABLE public.elections
  ADD COLUMN semaphore_group_frozen_at timestamptz;

CREATE TABLE public.semaphore_credential_issuances (
  election_id uuid NOT NULL REFERENCES public.elections(election_id) ON DELETE RESTRICT,
  voter_id uuid NOT NULL REFERENCES public.voters(voter_id) ON DELETE RESTRICT,
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (election_id, voter_id)
);

CREATE TABLE public.semaphore_group_members (
  election_id uuid NOT NULL REFERENCES public.elections(election_id) ON DELETE RESTRICT,
  member_index integer NOT NULL CHECK (member_index >= 0),
  identity_commitment numeric(78, 0) NOT NULL,
  added_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (election_id, member_index),
  CONSTRAINT semaphore_member_commitment_positive CHECK (identity_commitment > 0),
  CONSTRAINT semaphore_member_commitment_field_check CHECK (
    identity_commitment < 21888242871839275222246405745257275088548364400416034343698204186575808495617
  ),
  CONSTRAINT semaphore_member_unique_commitment UNIQUE (election_id, identity_commitment)
);

CREATE INDEX semaphore_group_members_order_idx
  ON public.semaphore_group_members (election_id, member_index);

ALTER TABLE public.semaphore_credential_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.semaphore_group_members ENABLE ROW LEVEL SECURITY;

GRANT SELECT ON TABLE public.semaphore_group_members TO anon, authenticated;
GRANT SELECT, INSERT ON TABLE public.semaphore_credential_issuances TO service_role;
GRANT SELECT, INSERT ON TABLE public.semaphore_group_members TO service_role;

CREATE POLICY published_semaphore_members_are_readable
  ON public.semaphore_group_members FOR SELECT
  TO anon, authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.elections election
      WHERE election.election_id = semaphore_group_members.election_id
        AND election.status <> 'draft'
    )
  );

CREATE OR REPLACE FUNCTION public.semaphore_group_members_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $function$
BEGIN
  RAISE EXCEPTION 'Semaphore group memberships are append-only';
END;
$function$;

CREATE TRIGGER semaphore_group_members_reject_update_delete
  BEFORE UPDATE OR DELETE ON public.semaphore_group_members
  FOR EACH ROW EXECUTE FUNCTION public.semaphore_group_members_reject_mutation();

CREATE OR REPLACE FUNCTION public.issue_semaphore_identity(
  p_election_id uuid,
  p_auth_user_id uuid,
  p_commitment text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  voter_row record;
  election_row record;
  commitment_value numeric;
  next_index integer;
  issued_before timestamptz;
BEGIN
  IF p_commitment !~ '^[1-9][0-9]{0,76}$' THEN
    RETURN pg_catalog.jsonb_build_object('eligible', false, 'invalid_commitment', true);
  END IF;
  commitment_value := p_commitment::numeric;
  IF commitment_value >= 21888242871839275222246405745257275088548364400416034343698204186575808495617 THEN
    RETURN pg_catalog.jsonb_build_object('eligible', false, 'invalid_commitment', true);
  END IF;

  SELECT election_id, status, starts_at, election_public_key, key_ceremony_status,
      semaphore_group_frozen_at
    INTO election_row
    FROM public.elections
    WHERE election_id = p_election_id
    FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false);
  END IF;
  IF election_row.status <> 'scheduled' OR election_row.starts_at <= pg_catalog.clock_timestamp() OR
      election_row.election_public_key IS NULL OR election_row.key_ceremony_status <> 'prototype_single_key' OR
      election_row.semaphore_group_frozen_at IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'open', false);
  END IF;

  SELECT voter_id, registration_status, email_verified_at
    INTO voter_row
    FROM public.voters
    WHERE auth_user_id = p_auth_user_id
    FOR UPDATE;
  IF NOT FOUND OR voter_row.registration_status <> 'approved' OR voter_row.email_verified_at IS NULL THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', false);
  END IF;

  SELECT issued_at INTO issued_before
    FROM public.semaphore_credential_issuances
    WHERE election_id = p_election_id AND voter_id = voter_row.voter_id;
  IF FOUND THEN
    IF EXISTS (
      SELECT 1 FROM public.semaphore_group_members
      WHERE election_id = p_election_id AND identity_commitment = commitment_value
    ) THEN
      RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', true, 'retry', true);
    END IF;
    RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', false, 'already_issued', true);
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.semaphore_group_members
    WHERE election_id = p_election_id AND identity_commitment = commitment_value
  ) THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', false, 'duplicate_commitment', true);
  END IF;

  SELECT COALESCE(pg_catalog.max(member_index) + 1, 0) INTO next_index
    FROM public.semaphore_group_members WHERE election_id = p_election_id;
  INSERT INTO public.semaphore_credential_issuances (election_id, voter_id)
    VALUES (p_election_id, voter_row.voter_id);
  INSERT INTO public.semaphore_group_members (election_id, member_index, identity_commitment)
    VALUES (p_election_id, next_index, commitment_value);

  RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', true, 'retry', false);
EXCEPTION WHEN unique_violation THEN
  RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', false, 'duplicate_commitment', true);
END;
$function$;

REVOKE ALL ON FUNCTION public.issue_semaphore_identity(uuid, uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.issue_semaphore_identity(uuid, uuid, text) TO service_role;
REVOKE ALL ON FUNCTION public.semaphore_group_members_reject_mutation() FROM PUBLIC, anon, authenticated, service_role;

ALTER TABLE public.accepted_ballots
  ALTER COLUMN nullifier SET NOT NULL,
  ADD CONSTRAINT accepted_ballot_nullifier_field_check CHECK (
    nullifier > 0 AND nullifier < 21888242871839275222246405745257275088548364400416034343698204186575808495617
  );

DROP FUNCTION public.record_accepted_ballot(uuid, text, text, jsonb);

CREATE FUNCTION public.record_accepted_ballot(
  p_election_id uuid,
  p_ballot_id text,
  p_ballot_hash_hex text,
  p_nullifier text,
  p_ballot_payload jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  election_row record;
  next_sequence bigint;
  previous_hash bytea;
  ballot_hash_bytes bytea;
  record_hash_bytes bytea;
  nullifier_value numeric;
  accepted_timestamp timestamptz;
BEGIN
  IF p_ballot_id !~ '^[a-f0-9]{64}$' OR p_ballot_hash_hex !~ '^[a-f0-9]{64}$' OR
      p_nullifier !~ '^[1-9][0-9]{0,76}$' OR pg_catalog.jsonb_typeof(p_ballot_payload) <> 'object' THEN
    RAISE EXCEPTION 'Invalid accepted ballot payload';
  END IF;
  nullifier_value := p_nullifier::numeric;
  IF nullifier_value >= 21888242871839275222246405745257275088548364400416034343698204186575808495617 THEN
    RAISE EXCEPTION 'Semaphore nullifier is outside the proof field';
  END IF;

  SELECT election_id, status, starts_at, ends_at
    INTO election_row
    FROM public.elections
    WHERE election_id = p_election_id
    FOR SHARE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false);
  END IF;
  IF election_row.status NOT IN ('active', 'scheduled') OR pg_catalog.clock_timestamp() < election_row.starts_at OR
      pg_catalog.clock_timestamp() >= election_row.ends_at THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'open', false);
  END IF;

  INSERT INTO public.election_ballot_chain_heads (election_id)
    VALUES (p_election_id) ON CONFLICT (election_id) DO NOTHING;
  SELECT last_sequence, last_hash INTO next_sequence, previous_hash
    FROM public.election_ballot_chain_heads WHERE election_id = p_election_id FOR UPDATE;

  next_sequence := next_sequence + 1;
  ballot_hash_bytes := pg_catalog.decode(p_ballot_hash_hex, 'hex');
  accepted_timestamp := pg_catalog.clock_timestamp();
  record_hash_bytes := extensions.digest(
    pg_catalog.uuid_send(p_election_id) || pg_catalog.int8send(next_sequence) ||
    previous_hash || ballot_hash_bytes || pg_catalog.convert_to(p_nullifier, 'UTF8'),
    'sha256'
  );

  BEGIN
    INSERT INTO public.accepted_ballots (
      election_id, ballot_sequence, ballot_id, ballot_hash, ballot_payload, nullifier,
      accepted_at, previous_hash, record_hash
    ) VALUES (
      p_election_id, next_sequence, p_ballot_id, ballot_hash_bytes, p_ballot_payload,
      nullifier_value, accepted_timestamp, previous_hash, record_hash_bytes
    );
  EXCEPTION WHEN unique_violation THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'duplicate', true);
  END;

  UPDATE public.election_ballot_chain_heads
    SET last_sequence = next_sequence, last_hash = record_hash_bytes
    WHERE election_id = p_election_id;
  RETURN pg_catalog.jsonb_build_object(
    'found', true,
    'open', true,
    'duplicate', false,
    'ballot_sequence', next_sequence,
    'previous_hash', pg_catalog.encode(previous_hash, 'hex'),
    'record_hash', pg_catalog.encode(record_hash_bytes, 'hex'),
    'accepted_at', accepted_timestamp
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.record_accepted_ballot(uuid, text, text, text, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_accepted_ballot(uuid, text, text, text, jsonb) TO service_role;
