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
  IF p_public_key IS NULL OR p_public_key !~ '^[a-f0-9]{64}$' THEN
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
  IF current_public_key IS NOT NULL OR current_key_status IS DISTINCT FROM 'not_started' THEN
    RETURN pg_catalog.jsonb_build_object(
      'found', true,
      'draft', true,
      'configured', false,
      'already_configured', true
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

REVOKE ALL ON FUNCTION public.configure_prototype_election_key(uuid, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.configure_prototype_election_key(uuid, text, text) TO service_role;
