DO $migration$
BEGIN
  IF EXISTS (SELECT 1 FROM public.accepted_ballots) THEN
    RAISE EXCEPTION 'Accepted ballots already exist; export and verify them before migrating the public proof commitment format.';
  END IF;
END;
$migration$;

ALTER TABLE public.accepted_ballots
  ADD COLUMN semaphore_proof_hash bytea NOT NULL,
  ADD CONSTRAINT accepted_ballot_semaphore_proof_hash_length CHECK (octet_length(semaphore_proof_hash) = 32);

DROP FUNCTION public.record_accepted_ballot(uuid, text, text, text, jsonb);

CREATE FUNCTION public.record_accepted_ballot(
  p_election_id uuid,
  p_ballot_id text,
  p_ballot_hash_hex text,
  p_nullifier text,
  p_semaphore_proof_hash_hex text,
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
  proof_hash_bytes bytea;
  record_hash_bytes bytea;
  nullifier_value numeric;
  accepted_timestamp timestamptz;
  duplicate_row record;
  is_same_ballot boolean;
BEGIN
  IF p_ballot_id !~ '^[a-f0-9]{64}$' OR p_ballot_hash_hex !~ '^[a-f0-9]{64}$' OR
      p_semaphore_proof_hash_hex !~ '^[a-f0-9]{64}$' OR
      p_nullifier IS NULL OR p_nullifier !~ '^[1-9][0-9]{0,76}$' OR
      pg_catalog.jsonb_typeof(p_ballot_payload) <> 'object' OR
      pg_catalog.jsonb_typeof(p_ballot_payload -> 'semaphoreProof') <> 'object' OR
      p_ballot_payload ->> 'nullifier' IS DISTINCT FROM p_nullifier OR
      (p_ballot_payload -> 'semaphoreProof' ->> 'nullifier') IS DISTINCT FROM p_nullifier THEN
    RAISE EXCEPTION 'Invalid accepted ballot payload';
  END IF;
  nullifier_value := p_nullifier::numeric;
  IF nullifier_value >= 21888242871839275222246405745257275088548364400416034343698204186575808495617 THEN
    RAISE EXCEPTION 'Semaphore nullifier is outside the proof field';
  END IF;
  ballot_hash_bytes := pg_catalog.decode(p_ballot_hash_hex, 'hex');
  proof_hash_bytes := pg_catalog.decode(p_semaphore_proof_hash_hex, 'hex');

  SELECT election_id, status, starts_at, ends_at
    INTO election_row
    FROM public.elections
    WHERE election_id = p_election_id
    FOR SHARE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false);
  END IF;
  IF election_row.status NOT IN ('active', 'scheduled') OR
      pg_catalog.clock_timestamp() < election_row.starts_at OR
      pg_catalog.clock_timestamp() >= election_row.ends_at THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'open', false);
  END IF;

  INSERT INTO public.election_ballot_chain_heads (election_id)
    VALUES (p_election_id) ON CONFLICT (election_id) DO NOTHING;
  SELECT last_sequence, last_hash INTO next_sequence, previous_hash
    FROM public.election_ballot_chain_heads WHERE election_id = p_election_id FOR UPDATE;

  SELECT ballot_sequence, ballot_id, ballot_hash, nullifier
    INTO duplicate_row
    FROM public.accepted_ballots
    WHERE election_id = p_election_id AND
      (ballot_hash = ballot_hash_bytes OR ballot_id = p_ballot_id OR nullifier = nullifier_value)
    LIMIT 1;
  IF FOUND THEN
    is_same_ballot := duplicate_row.ballot_id = p_ballot_id AND
      duplicate_row.ballot_hash = ballot_hash_bytes AND duplicate_row.nullifier = nullifier_value;
    RETURN pg_catalog.jsonb_build_object(
      'found', true, 'open', true, 'duplicate', true,
      'same_ballot', is_same_ballot, 'ballot_sequence', duplicate_row.ballot_sequence
    );
  END IF;

  next_sequence := next_sequence + 1;
  accepted_timestamp := pg_catalog.clock_timestamp();
  record_hash_bytes := extensions.digest(
    pg_catalog.uuid_send(p_election_id) || pg_catalog.int8send(next_sequence) ||
    previous_hash || ballot_hash_bytes || proof_hash_bytes ||
    pg_catalog.convert_to(p_nullifier, 'UTF8'),
    'sha256'
  );

  INSERT INTO public.accepted_ballots (
    election_id, ballot_sequence, ballot_id, ballot_hash, ballot_payload,
    semaphore_proof_hash, nullifier, accepted_at, previous_hash, record_hash
  ) VALUES (
    p_election_id, next_sequence, p_ballot_id, ballot_hash_bytes, p_ballot_payload,
    proof_hash_bytes, nullifier_value, accepted_timestamp, previous_hash, record_hash_bytes
  );
  INSERT INTO public.ballot_relay_status (election_id, ballot_sequence)
    VALUES (p_election_id, next_sequence);

  UPDATE public.election_ballot_chain_heads
    SET last_sequence = next_sequence, last_hash = record_hash_bytes
    WHERE election_id = p_election_id;
  RETURN pg_catalog.jsonb_build_object(
    'found', true, 'open', true, 'duplicate', false, 'same_ballot', false,
    'ballot_sequence', next_sequence,
    'previous_hash', pg_catalog.encode(previous_hash, 'hex'),
    'record_hash', pg_catalog.encode(record_hash_bytes, 'hex'),
    'accepted_at', accepted_timestamp
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.record_accepted_ballot(uuid, text, text, text, text, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_accepted_ballot(uuid, text, text, text, text, jsonb) TO service_role;
