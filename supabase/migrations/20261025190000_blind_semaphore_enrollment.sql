-- Move commitments out of the public group while enrollment is open. No time
-- or voter identifier is stored beside a pending commitment. At freeze, the
-- trusted API supplies a CSPRNG-shuffled order and its LeanIMT root.

DO $migration$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.semaphore_group_members member
    JOIN public.elections election USING (election_id)
    WHERE election.status <> 'scheduled'
       OR election.starts_at <= pg_catalog.clock_timestamp()
  ) THEN
    RAISE EXCEPTION 'Cannot randomize a Semaphore group after its election has started; resolve or archive those elections before applying this migration.';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.elections election
    WHERE election.semaphore_group_frozen_at IS NOT NULL
      AND (election.status <> 'scheduled' OR election.starts_at <= pg_catalog.clock_timestamp())
  ) THEN
    RAISE EXCEPTION 'Cannot reset a frozen Semaphore root after its election has started; resolve or archive those elections before applying this migration.';
  END IF;
END;
$migration$;

CREATE TABLE public.semaphore_pending_commitments (
  election_id uuid NOT NULL REFERENCES public.elections(election_id) ON DELETE RESTRICT,
  identity_commitment numeric(78, 0) NOT NULL,
  PRIMARY KEY (election_id, identity_commitment),
  CONSTRAINT semaphore_pending_commitment_positive CHECK (identity_commitment > 0),
  CONSTRAINT semaphore_pending_commitment_field_check CHECK (
    identity_commitment < 21888242871839275222246405745257275088548364400416034343698204186575808495617
  )
);

ALTER TABLE public.semaphore_pending_commitments ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, DELETE ON TABLE public.semaphore_pending_commitments TO service_role;
GRANT SELECT, INSERT ON TABLE public.semaphore_credential_issuances TO service_role;
GRANT INSERT, SELECT ON TABLE public.semaphore_group_members TO service_role;

-- If an upcoming election had already been frozen under the old timestamped
-- ordering, return its members to the untimed pending table and require a new
-- random-order freeze. The guard above prevents changing a group after opening.
INSERT INTO public.semaphore_pending_commitments (election_id, identity_commitment)
  SELECT election_id, identity_commitment FROM public.semaphore_group_members
  ON CONFLICT (election_id, identity_commitment) DO NOTHING;

DROP TRIGGER semaphore_group_members_reject_update_delete ON public.semaphore_group_members;
DELETE FROM public.semaphore_group_members;
CREATE TRIGGER semaphore_group_members_reject_mutation
  BEFORE UPDATE OR DELETE ON public.semaphore_group_members
  FOR EACH ROW EXECUTE FUNCTION public.semaphore_group_members_reject_mutation();

UPDATE public.elections
  SET semaphore_group_root = NULL,
      semaphore_group_frozen_at = NULL
  WHERE semaphore_group_frozen_at IS NOT NULL;

ALTER TABLE public.semaphore_group_members DROP COLUMN added_at;
ALTER TABLE public.semaphore_credential_issuances DROP COLUMN issued_at;

-- Retire the legacy direct voter-to-commitment mapping; the active flow uses
-- separate issuance and pending/group tables instead.
ALTER TABLE public.election_voters
  DROP CONSTRAINT IF EXISTS election_voters_commitment_length,
  DROP CONSTRAINT IF EXISTS election_voters_credential_check;
DROP INDEX IF EXISTS public.election_voters_commitment_uq;
ALTER TABLE public.election_voters
  DROP COLUMN eligibility_commitment,
  DROP COLUMN credential_issued_at;

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
  already_issued boolean;
BEGIN
  IF p_commitment IS NULL OR p_commitment !~ '^[1-9][0-9]{0,76}$' THEN
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

  SELECT EXISTS (
    SELECT 1 FROM public.semaphore_credential_issuances
    WHERE election_id = p_election_id AND voter_id = voter_row.voter_id
  ) INTO already_issued;
  IF already_issued THEN
    IF EXISTS (
      SELECT 1 FROM public.semaphore_pending_commitments
      WHERE election_id = p_election_id AND identity_commitment = commitment_value
    ) THEN
      RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', true, 'retry', true);
    END IF;
    RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', false, 'already_issued', true);
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.semaphore_pending_commitments
    WHERE election_id = p_election_id AND identity_commitment = commitment_value
  ) OR EXISTS (
    SELECT 1 FROM public.semaphore_group_members
    WHERE election_id = p_election_id AND identity_commitment = commitment_value
  ) THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', false, 'duplicate_commitment', true);
  END IF;

  INSERT INTO public.semaphore_credential_issuances (election_id, voter_id)
    VALUES (p_election_id, voter_row.voter_id);
  INSERT INTO public.semaphore_pending_commitments (election_id, identity_commitment)
    VALUES (p_election_id, commitment_value);

  RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', true, 'retry', false);
EXCEPTION WHEN unique_violation THEN
  RETURN pg_catalog.jsonb_build_object('found', true, 'eligible', false, 'duplicate_commitment', true);
END;
$function$;

DROP FUNCTION public.freeze_semaphore_group(uuid, text, integer, text);

CREATE FUNCTION public.freeze_semaphore_group(
  p_election_id uuid,
  p_group_root text,
  p_commitments text[],
  p_admin_email text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  election_row record;
  actual_count integer;
  root_value numeric;
  commitment_text text;
  commitment_value numeric;
  unique_count integer;
BEGIN
  IF p_group_root IS NULL OR p_group_root !~ '^[1-9][0-9]{0,76}$' THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'valid', false);
  END IF;
  root_value := p_group_root::numeric;
  IF root_value >= 21888242871839275222246405745257275088548364400416034343698204186575808495617 THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'valid', false);
  END IF;

  SELECT election_id, status, starts_at, semaphore_group_root, semaphore_group_frozen_at
    INTO election_row
    FROM public.elections WHERE election_id = p_election_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false);
  END IF;
  IF election_row.semaphore_group_frozen_at IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'found', true,
      'frozen', election_row.semaphore_group_root = root_value,
      'same_root', election_row.semaphore_group_root = root_value
    );
  END IF;
  IF election_row.status <> 'scheduled' OR election_row.starts_at <= pg_catalog.clock_timestamp() THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'open', false);
  END IF;
  IF p_commitments IS NULL OR pg_catalog.cardinality(p_commitments) < 3 THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'valid', false);
  END IF;

  FOREACH commitment_text IN ARRAY p_commitments LOOP
    IF commitment_text IS NULL OR commitment_text !~ '^[1-9][0-9]{0,76}$' THEN
      RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'valid', false);
    END IF;
    commitment_value := commitment_text::numeric;
    IF commitment_value >= 21888242871839275222246405745257275088548364400416034343698204186575808495617 THEN
      RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'valid', false);
    END IF;
  END LOOP;
  SELECT pg_catalog.count(DISTINCT supplied.value) INTO unique_count
    FROM pg_catalog.unnest(p_commitments) AS supplied(value);
  IF unique_count <> pg_catalog.cardinality(p_commitments) THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'valid', false);
  END IF;

  SELECT pg_catalog.count(*) INTO actual_count
    FROM public.semaphore_pending_commitments WHERE election_id = p_election_id;
  IF actual_count <> pg_catalog.cardinality(p_commitments) OR actual_count < 3 OR EXISTS (
    SELECT identity_commitment
      FROM public.semaphore_pending_commitments WHERE election_id = p_election_id
    EXCEPT
    SELECT supplied.value::numeric FROM pg_catalog.unnest(p_commitments) AS supplied(value)
  ) OR EXISTS (
    SELECT supplied.value::numeric FROM pg_catalog.unnest(p_commitments) AS supplied(value)
    EXCEPT
    SELECT identity_commitment
      FROM public.semaphore_pending_commitments WHERE election_id = p_election_id
  ) THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'valid', false);
  END IF;

  INSERT INTO public.semaphore_group_members (election_id, member_index, identity_commitment)
    SELECT p_election_id, (supplied.ordinality - 1)::integer, supplied.value::numeric
    FROM pg_catalog.unnest(p_commitments) WITH ORDINALITY AS supplied(value, ordinality);
  DELETE FROM public.semaphore_pending_commitments WHERE election_id = p_election_id;
  UPDATE public.elections
    SET semaphore_group_root = root_value,
        semaphore_group_frozen_at = pg_catalog.clock_timestamp()
    WHERE election_id = p_election_id;
  INSERT INTO public.audit_events (actor_kind, actor_label, action_code, subject_election_id)
    VALUES ('admin', pg_catalog.lower(pg_catalog.btrim(p_admin_email)),
      'election.semaphore_group_frozen', p_election_id);

  RETURN pg_catalog.jsonb_build_object(
    'found', true, 'frozen', true, 'valid', true, 'member_count', actual_count
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.issue_semaphore_identity(uuid, uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.issue_semaphore_identity(uuid, uuid, text) TO service_role;
REVOKE ALL ON FUNCTION public.freeze_semaphore_group(uuid, text, text[], text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.freeze_semaphore_group(uuid, text, text[], text) TO service_role;
