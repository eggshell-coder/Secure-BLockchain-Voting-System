ALTER TABLE public.elections
  ADD COLUMN semaphore_group_root numeric(78, 0),
  ADD CONSTRAINT elections_semaphore_root_field_check CHECK (
    semaphore_group_root IS NULL OR
    (semaphore_group_root > 0 AND semaphore_group_root < 21888242871839275222246405745257275088548364400416034343698204186575808495617)
  ),
  ADD CONSTRAINT elections_semaphore_freeze_consistency_check CHECK (
    (semaphore_group_root IS NULL AND semaphore_group_frozen_at IS NULL) OR
    (semaphore_group_root IS NOT NULL AND semaphore_group_frozen_at IS NOT NULL)
  );

INSERT INTO public.audit_action_types (action_code, description) VALUES
  ('election.semaphore_group_frozen', 'The election Semaphore membership group was frozen.')
ON CONFLICT (action_code) DO NOTHING;

CREATE OR REPLACE FUNCTION public.freeze_semaphore_group(
  p_election_id uuid,
  p_group_root text,
  p_member_count integer,
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
BEGIN
  IF p_group_root !~ '^[1-9][0-9]{0,76}$' OR p_member_count < 3 THEN
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
  IF election_row.status <> 'scheduled' OR election_row.starts_at <= pg_catalog.clock_timestamp() THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'open', false);
  END IF;
  SELECT pg_catalog.count(*) INTO actual_count
    FROM public.semaphore_group_members WHERE election_id = p_election_id;
  IF actual_count <> p_member_count OR actual_count < 3 THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', false, 'valid', false);
  END IF;
  IF election_row.semaphore_group_frozen_at IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'found', true,
      'frozen', election_row.semaphore_group_root = root_value,
      'same_root', election_row.semaphore_group_root = root_value
    );
  END IF;

  UPDATE public.elections
    SET semaphore_group_root = root_value,
        semaphore_group_frozen_at = pg_catalog.clock_timestamp()
    WHERE election_id = p_election_id;
  INSERT INTO public.audit_events (actor_kind, actor_label, action_code, subject_election_id)
    VALUES ('admin', pg_catalog.lower(pg_catalog.btrim(p_admin_email)),
      'election.semaphore_group_frozen', p_election_id);

  RETURN pg_catalog.jsonb_build_object('found', true, 'frozen', true, 'member_count', actual_count);
END;
$function$;

REVOKE ALL ON FUNCTION public.freeze_semaphore_group(uuid, text, integer, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.freeze_semaphore_group(uuid, text, integer, text) TO service_role;
