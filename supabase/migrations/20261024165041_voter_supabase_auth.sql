-- Link voter registrations to a verified Supabase Auth identity.
-- The Auth identity is used only for registration and eligibility review; it
-- must never be joined to anonymous ballot events or ballot selections.

ALTER TABLE public.voters
  ADD COLUMN auth_user_id uuid REFERENCES auth.users(id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX voters_auth_user_id_uq
  ON public.voters (auth_user_id)
  WHERE auth_user_id IS NOT NULL;

COMMENT ON COLUMN public.voters.auth_user_id IS
  'Verified Supabase Auth identity for registration only. Never associate it with a ballot nullifier or choice.';

CREATE OR REPLACE FUNCTION public.register_authenticated_voter(
  p_auth_user_id uuid,
  p_organization_id text,
  p_full_name text,
  p_email text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  normalized_org text := pg_catalog.btrim(p_organization_id);
  normalized_email text := pg_catalog.lower(pg_catalog.btrim(p_email));
  existing_voter record;
  matching_count bigint;
  target_voter_id uuid;
BEGIN
  IF p_auth_user_id IS NULL
     OR normalized_org IS NULL
     OR pg_catalog.char_length(normalized_org) NOT BETWEEN 3 AND 80
     OR p_full_name IS NULL
     OR pg_catalog.char_length(pg_catalog.btrim(p_full_name)) NOT BETWEEN 2 AND 120
     OR normalized_email IS NULL
     OR pg_catalog.char_length(normalized_email) NOT BETWEEN 3 AND 254 THEN
    RETURN pg_catalog.jsonb_build_object('ok', false, 'invalid', true);
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('voter-org:' || pg_catalog.lower(normalized_org), 0)
  );
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('voter-auth:' || p_auth_user_id::text, 0)
  );

  SELECT pg_catalog.count(*)
    INTO matching_count
    FROM public.voters
    WHERE pg_catalog.lower(organization_id) = pg_catalog.lower(normalized_org)
       OR auth_user_id = p_auth_user_id;

  IF matching_count > 0 THEN
    SELECT voter_id, auth_user_id, organization_id, email, registration_status
      INTO existing_voter
      FROM public.voters
      WHERE auth_user_id = p_auth_user_id
      LIMIT 1;

    IF FOUND
       AND pg_catalog.lower(existing_voter.organization_id) = pg_catalog.lower(normalized_org)
       AND existing_voter.email = normalized_email THEN
      RETURN pg_catalog.jsonb_build_object(
        'ok', true,
        'created', false,
        'voter_id', existing_voter.voter_id,
        'status', existing_voter.registration_status
      );
    END IF;

    RETURN pg_catalog.jsonb_build_object('ok', false, 'conflict', true);
  END IF;

  INSERT INTO public.voters (
    auth_user_id,
    organization_id,
    full_name,
    email,
    email_verified_at
  ) VALUES (
    p_auth_user_id,
    normalized_org,
    pg_catalog.btrim(p_full_name),
    normalized_email,
    pg_catalog.clock_timestamp()
  )
  RETURNING voter_id INTO target_voter_id;

  INSERT INTO public.audit_events (actor_kind, actor_user_id, action_code, subject_voter_id)
  VALUES ('user', p_auth_user_id, 'voter.registered', target_voter_id);

  INSERT INTO public.audit_events (actor_kind, actor_user_id, action_code, subject_voter_id)
  VALUES ('user', p_auth_user_id, 'voter.email_verified', target_voter_id);

  RETURN pg_catalog.jsonb_build_object(
    'ok', true,
    'created', true,
    'voter_id', target_voter_id,
    'status', 'pending'
  );
EXCEPTION
  WHEN unique_violation THEN
    RETURN pg_catalog.jsonb_build_object('ok', false, 'conflict', true);
END;
$function$;

REVOKE ALL ON FUNCTION public.register_authenticated_voter(uuid, text, text, text)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.register_authenticated_voter(uuid, text, text, text)
  TO service_role;

-- Retire the local-only OTP RPCs so the server cannot accidentally keep using
-- generated development codes as an identity-verification mechanism.
REVOKE ALL ON FUNCTION public.register_voter(text, text, text, text, timestamptz)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.verify_voter_otp(text, text)
  FROM PUBLIC, anon, authenticated, service_role;;
