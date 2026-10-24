-- Prototype election keys: the public key is election configuration, while the
-- secret key remains in a separate local trustee/admin file.
ALTER TABLE public.elections
  ADD COLUMN election_public_key text,
  ADD COLUMN key_ceremony_status text NOT NULL DEFAULT 'not_started';

ALTER TABLE public.elections
  ADD CONSTRAINT elections_public_key_hex_check CHECK (
    election_public_key IS NULL OR election_public_key ~ '^[a-f0-9]{64}$'
  ),
  ADD CONSTRAINT elections_key_ceremony_status_check CHECK (
    key_ceremony_status IN ('not_started', 'prototype_single_key', 'threshold_2_of_3')
  ),
  ADD CONSTRAINT elections_key_status_consistency_check CHECK (
    (election_public_key IS NULL AND key_ceremony_status = 'not_started') OR
    (election_public_key IS NOT NULL AND key_ceremony_status IN ('prototype_single_key', 'threshold_2_of_3'))
  );

INSERT INTO public.audit_action_types (action_code, description) VALUES
  ('election.prototype_key_generated', 'A prototype single-admin election key was configured.'),
  ('election.threshold_key_configured', 'A trustee threshold election key was configured.')
ON CONFLICT (action_code) DO NOTHING;

CREATE OR REPLACE FUNCTION public.configure_prototype_election_key(
  p_election_id uuid,
  p_public_key text,
  p_admin_email text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  current_status text;
  current_public_key text;
  current_key_status text;
BEGIN
  IF p_public_key !~ '^[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'Invalid election public key encoding';
  END IF;

  SELECT status, election_public_key, key_ceremony_status
    INTO current_status, current_public_key, current_key_status
    FROM public.elections
    WHERE election_id = p_election_id
    FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false);
  END IF;
  IF current_status <> 'draft' THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'draft', false, 'configured', false);
  END IF;
  IF current_public_key IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'found', true,
      'draft', true,
      'configured', current_public_key = p_public_key AND current_key_status = 'prototype_single_key'
    );
  END IF;

  UPDATE public.elections
    SET election_public_key = p_public_key,
        key_ceremony_status = 'prototype_single_key'
    WHERE election_id = p_election_id;
  INSERT INTO public.audit_events (actor_kind, actor_label, action_code, subject_election_id)
    VALUES ('admin', pg_catalog.lower(pg_catalog.btrim(p_admin_email)),
      'election.prototype_key_generated', p_election_id);

  RETURN pg_catalog.jsonb_build_object('found', true, 'draft', true, 'configured', true);
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
  key_configured boolean;
  candidate_count integer;
BEGIN
  SELECT status,
      election_public_key IS NOT NULL AND key_ceremony_status IN ('prototype_single_key', 'threshold_2_of_3')
    INTO current_status, key_configured
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
  IF p_status <> 'scheduled' OR p_manifest_hash_hex !~ '^[0-9a-fA-F]{64}$' THEN
    RAISE EXCEPTION 'Invalid publication manifest';
  END IF;
  IF NOT key_configured THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'draft', true, 'complete', true, 'key_configured', false);
  END IF;

  UPDATE public.elections
    SET status = p_status, manifest_hash = pg_catalog.decode(p_manifest_hash_hex, 'hex')
    WHERE election_id = p_election_id;
  INSERT INTO public.audit_events (actor_kind, actor_label, action_code, subject_election_id)
    VALUES ('admin', pg_catalog.lower(pg_catalog.btrim(p_admin_email)), 'election.published', p_election_id);

  RETURN pg_catalog.jsonb_build_object('found', true, 'draft', true, 'complete', true, 'key_configured', true);
END;
$function$;

REVOKE ALL ON FUNCTION public.configure_prototype_election_key(uuid, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.configure_prototype_election_key(uuid, text, text) TO service_role;
REVOKE ALL ON FUNCTION public.publish_election(uuid, text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.publish_election(uuid, text, text, text) TO service_role;
