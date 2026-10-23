-- Atomic server-side workflows for the Node API. These functions run as the
-- calling role (service_role) and are not executable by browser roles.

ALTER TABLE public.audit_events
  ADD COLUMN actor_label text;

ALTER TABLE public.audit_events
  DROP CONSTRAINT audit_actor_kind_check,
  DROP CONSTRAINT audit_actor_identity_check;

ALTER TABLE public.audit_events
  ADD CONSTRAINT audit_actor_kind_check
    CHECK (actor_kind IN ('admin', 'user', 'system', 'indexer')),
  ADD CONSTRAINT audit_actor_identity_check CHECK (
    (actor_kind = 'user') = (actor_user_id IS NOT NULL)
    AND (actor_kind = 'admin') = (actor_label IS NOT NULL)
  );

INSERT INTO public.audit_action_types (action_code, description) VALUES
  ('admin.login', 'An administrator signed in.'),
  ('admin.logout', 'An administrator signed out.'),
  ('voter.email_verification_code_sent', 'A voter email verification challenge was issued.')
ON CONFLICT (action_code) DO NOTHING;

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
    'actor_label', NEW.actor_label,
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

CREATE OR REPLACE FUNCTION public.register_voter(
  p_organization_id text,
  p_full_name text,
  p_email text,
  p_secret_hash_hex text,
  p_expires_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  normalized_org text := pg_catalog.btrim(p_organization_id);
  existing_voter record;
  target_voter_id uuid;
  target_challenge_id uuid;
  was_created boolean := false;
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(pg_catalog.lower(normalized_org), 0));

  SELECT voter_id, email_verified_at, registration_status
    INTO existing_voter
    FROM public.voters
    WHERE pg_catalog.lower(organization_id) = pg_catalog.lower(normalized_org)
    FOR UPDATE;

  IF FOUND AND (existing_voter.email_verified_at IS NOT NULL OR existing_voter.registration_status <> 'pending') THEN
    RETURN pg_catalog.jsonb_build_object('ok', false, 'conflict', true);
  END IF;

  IF FOUND THEN
    target_voter_id := existing_voter.voter_id;
    UPDATE public.voters
      SET full_name = p_full_name, email = pg_catalog.lower(pg_catalog.btrim(p_email))
      WHERE voter_id = target_voter_id;
  ELSE
    INSERT INTO public.voters (organization_id, full_name, email)
      VALUES (normalized_org, p_full_name, pg_catalog.lower(pg_catalog.btrim(p_email)))
      RETURNING voter_id INTO target_voter_id;
    was_created := true;
  END IF;

  UPDATE public.verification_challenges
    SET status = 'superseded'
    WHERE voter_id = target_voter_id AND purpose = 'email_verification' AND status = 'active';

  INSERT INTO public.verification_challenges (voter_id, secret_hash, expires_at)
    VALUES (target_voter_id, pg_catalog.decode(p_secret_hash_hex, 'hex'), p_expires_at)
    RETURNING challenge_id INTO target_challenge_id;

  IF was_created THEN
    INSERT INTO public.audit_events (actor_kind, action_code, subject_voter_id)
      VALUES ('system', 'voter.registered', target_voter_id);
  END IF;
  INSERT INTO public.audit_events (actor_kind, action_code, subject_challenge_id)
    VALUES ('system', 'voter.email_verification_code_sent', target_challenge_id);

  RETURN pg_catalog.jsonb_build_object('ok', true, 'voter_id', target_voter_id, 'created', was_created);
END;
$function$;

CREATE OR REPLACE FUNCTION public.verify_voter_otp(
  p_organization_id text,
  p_secret_hash_hex text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  target_voter record;
  target_challenge record;
  new_attempt_count smallint;
BEGIN
  SELECT voter_id, registration_status, email_verified_at
    INTO target_voter
    FROM public.voters
    WHERE pg_catalog.lower(organization_id) = pg_catalog.lower(pg_catalog.btrim(p_organization_id))
    FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('ok', false);
  END IF;

  SELECT challenge_id, secret_hash, expires_at, attempt_count
    INTO target_challenge
    FROM public.verification_challenges
    WHERE voter_id = target_voter.voter_id
      AND purpose = 'email_verification'
      AND status = 'active'
    FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('ok', false);
  END IF;

  IF target_challenge.expires_at <= pg_catalog.clock_timestamp() THEN
    UPDATE public.verification_challenges SET status = 'expired'
      WHERE challenge_id = target_challenge.challenge_id;
    RETURN pg_catalog.jsonb_build_object('ok', false);
  END IF;

  IF target_challenge.attempt_count >= 5 THEN
    UPDATE public.verification_challenges SET status = 'locked'
      WHERE challenge_id = target_challenge.challenge_id;
    RETURN pg_catalog.jsonb_build_object('ok', false);
  END IF;

  IF target_challenge.secret_hash <> pg_catalog.decode(p_secret_hash_hex, 'hex') THEN
    new_attempt_count := target_challenge.attempt_count + 1;
    UPDATE public.verification_challenges
      SET attempt_count = new_attempt_count,
          status = CASE WHEN new_attempt_count >= 5 THEN 'locked' ELSE 'active' END
      WHERE challenge_id = target_challenge.challenge_id;
    RETURN pg_catalog.jsonb_build_object('ok', false);
  END IF;

  UPDATE public.verification_challenges
    SET status = 'consumed', consumed_at = pg_catalog.clock_timestamp()
    WHERE challenge_id = target_challenge.challenge_id;
  UPDATE public.voters
    SET email_verified_at = COALESCE(email_verified_at, pg_catalog.clock_timestamp())
    WHERE voter_id = target_voter.voter_id;
  INSERT INTO public.audit_events (actor_kind, action_code, subject_voter_id)
    VALUES ('system', 'voter.email_verified', target_voter.voter_id);

  RETURN pg_catalog.jsonb_build_object(
    'ok', true,
    'status', target_voter.registration_status
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.review_voter_registration(
  p_voter_id uuid,
  p_decision text,
  p_admin_email text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  target_voter record;
BEGIN
  IF p_decision NOT IN ('approved', 'rejected') THEN
    RAISE EXCEPTION 'Invalid registration decision';
  END IF;

  SELECT voter_id, registration_status, email_verified_at
    INTO target_voter
    FROM public.voters
    WHERE voter_id = p_voter_id
    FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false);
  END IF;
  IF target_voter.registration_status <> 'pending' THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'changed', false);
  END IF;
  IF p_decision = 'approved' AND target_voter.email_verified_at IS NULL THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'verified', false);
  END IF;

  UPDATE public.voters
    SET registration_status = p_decision,
        registration_reviewed_at = pg_catalog.clock_timestamp()
    WHERE voter_id = p_voter_id;
  INSERT INTO public.audit_events (actor_kind, actor_label, action_code, subject_voter_id)
    VALUES ('admin', pg_catalog.lower(pg_catalog.btrim(p_admin_email)),
      CASE WHEN p_decision = 'approved' THEN 'voter.approved' ELSE 'voter.rejected' END,
      p_voter_id);

  RETURN pg_catalog.jsonb_build_object('found', true, 'changed', true, 'status', p_decision);
END;
$function$;

CREATE OR REPLACE FUNCTION public.create_election_with_candidates(
  p_title text,
  p_description text,
  p_starts_at timestamptz,
  p_ends_at timestamptz,
  p_candidates jsonb,
  p_admin_email text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  target_election_id uuid;
  candidate_item record;
BEGIN
  INSERT INTO public.elections (title, description, starts_at, ends_at)
    VALUES (p_title, p_description, p_starts_at, p_ends_at)
    RETURNING election_id INTO target_election_id;

  FOR candidate_item IN
    SELECT value, ordinality
    FROM pg_catalog.jsonb_array_elements(p_candidates) WITH ORDINALITY
  LOOP
    INSERT INTO public.candidates (election_id, display_name, manifesto, list_order)
      VALUES (
        target_election_id,
        candidate_item.value ->> 'name',
        COALESCE(candidate_item.value ->> 'manifesto', ''),
        candidate_item.ordinality::smallint
      );
  END LOOP;

  INSERT INTO public.audit_events (actor_kind, actor_label, action_code, subject_election_id)
    VALUES ('admin', pg_catalog.lower(pg_catalog.btrim(p_admin_email)), 'election.created', target_election_id);

  RETURN target_election_id;
END;
$function$;

CREATE OR REPLACE FUNCTION public.publish_election(
  p_election_id uuid,
  p_status text,
  p_manifest_hash_hex text,
  p_admin_email text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  current_status text;
  candidate_count integer;
BEGIN
  SELECT status INTO current_status
    FROM public.elections WHERE election_id = p_election_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false);
  END IF;
  IF current_status <> 'draft' THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'draft', false);
  END IF;
  SELECT pg_catalog.count(*) INTO candidate_count
    FROM public.candidates WHERE election_id = p_election_id;
  IF candidate_count < 2 THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'draft', true, 'complete', false);
  END IF;
  IF p_status NOT IN ('scheduled', 'active', 'closed') OR p_manifest_hash_hex !~ '^[0-9a-fA-F]{64}$' THEN
    RAISE EXCEPTION 'Invalid publication manifest';
  END IF;

  UPDATE public.elections
    SET status = p_status, manifest_hash = pg_catalog.decode(p_manifest_hash_hex, 'hex')
    WHERE election_id = p_election_id;
  INSERT INTO public.audit_events (actor_kind, actor_label, action_code, subject_election_id)
    VALUES ('admin', pg_catalog.lower(pg_catalog.btrim(p_admin_email)), 'election.published', p_election_id);

  RETURN pg_catalog.jsonb_build_object('found', true, 'draft', true, 'complete', true);
END;
$function$;

CREATE OR REPLACE FUNCTION public.audit_admin_event(p_admin_email text, p_action_code text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
BEGIN
  IF p_action_code NOT IN ('admin.login', 'admin.logout') THEN
    RAISE EXCEPTION 'Invalid admin audit action';
  END IF;
  INSERT INTO public.audit_events (actor_kind, actor_label, action_code)
    VALUES ('admin', pg_catalog.lower(pg_catalog.btrim(p_admin_email)), p_action_code);
  RETURN true;
END;
$function$;

CREATE OR REPLACE FUNCTION public.audit_chain_is_valid()
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  event_row record;
  expected_previous bytea := pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex');
  expected_hash bytea;
  event_payload text;
BEGIN
  FOR event_row IN SELECT * FROM public.audit_events ORDER BY event_sequence LOOP
    IF event_row.previous_hash <> expected_previous THEN
      RETURN false;
    END IF;
    event_payload := pg_catalog.jsonb_build_object(
      'event_sequence', event_row.event_sequence,
      'actor_kind', event_row.actor_kind,
      'actor_user_id', event_row.actor_user_id,
      'actor_label', event_row.actor_label,
      'action_code', event_row.action_code,
      'subject_voter_id', event_row.subject_voter_id,
      'subject_election_id', event_row.subject_election_id,
      'subject_candidate_id', event_row.subject_candidate_id,
      'subject_challenge_id', event_row.subject_challenge_id,
      'request_id', event_row.request_id,
      'occurred_at_utc', pg_catalog.to_char(
        event_row.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'
      ),
      'previous_hash', pg_catalog.encode(event_row.previous_hash, 'hex')
    )::text;
    expected_hash := extensions.digest(pg_catalog.convert_to(event_payload, 'UTF8'), 'sha256');
    IF event_row.event_hash <> expected_hash THEN
      RETURN false;
    END IF;
    expected_previous := event_row.event_hash;
  END LOOP;
  RETURN true;
END;
$function$;

REVOKE ALL ON FUNCTION public.register_voter(text, text, text, text, timestamptz) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.verify_voter_otp(text, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.review_voter_registration(uuid, text, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.create_election_with_candidates(text, text, timestamptz, timestamptz, jsonb, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.publish_election(uuid, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.audit_admin_event(text, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.audit_chain_is_valid() FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.register_voter(text, text, text, text, timestamptz) TO service_role;
GRANT EXECUTE ON FUNCTION public.verify_voter_otp(text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.review_voter_registration(uuid, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.create_election_with_candidates(text, text, timestamptz, timestamptz, jsonb, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.publish_election(uuid, text, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.audit_admin_event(text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.audit_chain_is_valid() TO service_role;

REVOKE ALL ON FUNCTION public.audit_events_chain_before_insert() FROM PUBLIC, anon, authenticated, service_role;
