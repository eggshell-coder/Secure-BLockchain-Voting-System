INSERT INTO public.audit_action_types (action_code, description) VALUES
  ('election.reopened_for_key_setup', 'A scheduled election was returned to draft before opening so its missing key could be configured.')
ON CONFLICT (action_code) DO NOTHING;

CREATE OR REPLACE FUNCTION public.reopen_election_for_key_setup(
  p_election_id uuid,
  p_admin_email text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  election_row record;
  has_activity boolean;
BEGIN
  IF p_admin_email IS NULL OR pg_catalog.btrim(p_admin_email) = '' THEN
    RAISE EXCEPTION 'Administrator identity is required';
  END IF;

  SELECT status, starts_at, election_public_key, key_ceremony_status,
      manifest_hash, semaphore_group_root, semaphore_group_frozen_at
    INTO election_row
    FROM public.elections
    WHERE election_id = p_election_id
    FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false, 'ready', false, 'reason', 'not_found');
  END IF;

  IF election_row.election_public_key IS NOT NULL
     OR election_row.key_ceremony_status IS DISTINCT FROM 'not_started' THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'ready', false, 'reason', 'key_configured');
  END IF;
  IF election_row.semaphore_group_root IS NOT NULL
     OR election_row.semaphore_group_frozen_at IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'ready', false, 'reason', 'group_frozen');
  END IF;
  IF election_row.starts_at <= pg_catalog.clock_timestamp() THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'ready', false, 'reason', 'already_started');
  END IF;

  SELECT
    EXISTS (SELECT 1 FROM public.accepted_ballots WHERE election_id = p_election_id)
    OR EXISTS (SELECT 1 FROM public.ballot_relay_status WHERE election_id = p_election_id)
    OR EXISTS (SELECT 1 FROM public.semaphore_credential_issuances WHERE election_id = p_election_id)
    OR EXISTS (SELECT 1 FROM public.semaphore_group_members WHERE election_id = p_election_id)
    OR EXISTS (SELECT 1 FROM public.semaphore_pending_commitments WHERE election_id = p_election_id)
    OR EXISTS (SELECT 1 FROM public.election_chain_deployments WHERE election_id = p_election_id)
    OR EXISTS (SELECT 1 FROM public.candidate_results WHERE election_id = p_election_id)
    INTO has_activity;
  IF has_activity THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'ready', false, 'reason', 'activity_exists');
  END IF;

  IF election_row.status = 'draft' AND election_row.manifest_hash IS NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'found', true, 'ready', true, 'reopened', false, 'republish_required', true
    );
  END IF;
  IF election_row.status <> 'scheduled' THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'ready', false, 'reason', 'not_scheduled');
  END IF;

  UPDATE public.elections
    SET status = 'draft', manifest_hash = NULL
    WHERE election_id = p_election_id;

  INSERT INTO public.audit_events (actor_kind, actor_label, action_code, subject_election_id)
    VALUES (
      'admin',
      pg_catalog.lower(pg_catalog.btrim(p_admin_email)),
      'election.reopened_for_key_setup',
      p_election_id
    );

  RETURN pg_catalog.jsonb_build_object(
    'found', true, 'ready', true, 'reopened', true, 'republish_required', true
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.reopen_election_for_key_setup(uuid, text)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.reopen_election_for_key_setup(uuid, text)
  TO service_role;
