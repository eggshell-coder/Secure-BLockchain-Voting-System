CREATE TABLE public.ballot_relay_status (
  election_id uuid NOT NULL,
  ballot_sequence bigint NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  transaction_hash bytea,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (election_id, ballot_sequence),
  CONSTRAINT ballot_relay_status_fk FOREIGN KEY (election_id, ballot_sequence)
    REFERENCES public.accepted_ballots(election_id, ballot_sequence) ON DELETE RESTRICT,
  CONSTRAINT ballot_relay_status_check CHECK (status IN ('pending', 'relayed')),
  CONSTRAINT ballot_relay_tx_hash_check CHECK (transaction_hash IS NULL OR octet_length(transaction_hash) = 32),
  CONSTRAINT ballot_relay_tx_state_check CHECK (
    (status = 'pending' AND transaction_hash IS NULL) OR status = 'relayed'
  )
);

ALTER TABLE public.ballot_relay_status ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON TABLE public.ballot_relay_status TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.ballot_relay_status TO service_role;

CREATE POLICY published_ballot_relay_status_is_readable
  ON public.ballot_relay_status FOR SELECT
  TO anon, authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.elections election
      WHERE election.election_id = ballot_relay_status.election_id
        AND election.status <> 'draft'
    )
  );

DROP FUNCTION public.record_accepted_ballot(uuid, text, text, text, jsonb);

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
  duplicate_row record;
  is_same_ballot boolean;
BEGIN
  IF p_ballot_id !~ '^[a-f0-9]{64}$' OR p_ballot_hash_hex !~ '^[a-f0-9]{64}$' OR
      p_nullifier IS NULL OR p_nullifier !~ '^[1-9][0-9]{0,76}$' OR
      pg_catalog.jsonb_typeof(p_ballot_payload) <> 'object' THEN
    RAISE EXCEPTION 'Invalid accepted ballot payload';
  END IF;
  nullifier_value := p_nullifier::numeric;
  IF nullifier_value >= 21888242871839275222246405745257275088548364400416034343698204186575808495617 THEN
    RAISE EXCEPTION 'Semaphore nullifier is outside the proof field';
  END IF;
  ballot_hash_bytes := pg_catalog.decode(p_ballot_hash_hex, 'hex');

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
      'found', true,
      'open', true,
      'duplicate', true,
      'same_ballot', is_same_ballot,
      'ballot_sequence', duplicate_row.ballot_sequence
    );
  END IF;

  next_sequence := next_sequence + 1;
  accepted_timestamp := pg_catalog.clock_timestamp();
  record_hash_bytes := extensions.digest(
    pg_catalog.uuid_send(p_election_id) || pg_catalog.int8send(next_sequence) ||
    previous_hash || ballot_hash_bytes || pg_catalog.convert_to(p_nullifier, 'UTF8'),
    'sha256'
  );

  INSERT INTO public.accepted_ballots (
    election_id, ballot_sequence, ballot_id, ballot_hash, ballot_payload, nullifier,
    accepted_at, previous_hash, record_hash
  ) VALUES (
    p_election_id, next_sequence, p_ballot_id, ballot_hash_bytes, p_ballot_payload,
    nullifier_value, accepted_timestamp, previous_hash, record_hash_bytes
  );
  INSERT INTO public.ballot_relay_status (election_id, ballot_sequence)
    VALUES (p_election_id, next_sequence);

  UPDATE public.election_ballot_chain_heads
    SET last_sequence = next_sequence, last_hash = record_hash_bytes
    WHERE election_id = p_election_id;
  RETURN pg_catalog.jsonb_build_object(
    'found', true,
    'open', true,
    'duplicate', false,
    'same_ballot', false,
    'ballot_sequence', next_sequence,
    'previous_hash', pg_catalog.encode(previous_hash, 'hex'),
    'record_hash', pg_catalog.encode(record_hash_bytes, 'hex'),
    'accepted_at', accepted_timestamp
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.mark_ballot_relayed(
  p_election_id uuid,
  p_ballot_sequence bigint,
  p_transaction_hash text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  transaction_hash_bytes bytea;
BEGIN
  IF p_transaction_hash IS NULL THEN
    transaction_hash_bytes := NULL;
  ELSIF p_transaction_hash ~ '^0x[0-9a-fA-F]{64}$' THEN
    transaction_hash_bytes := pg_catalog.decode(pg_catalog.substr(p_transaction_hash, 3), 'hex');
  ELSE
    RAISE EXCEPTION 'Invalid transaction hash';
  END IF;

  UPDATE public.ballot_relay_status
    SET status = 'relayed', transaction_hash = transaction_hash_bytes,
        updated_at = pg_catalog.clock_timestamp()
    WHERE election_id = p_election_id AND ballot_sequence = p_ballot_sequence;
  RETURN FOUND;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_accepted_ballot(uuid, text, text, text, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_accepted_ballot(uuid, text, text, text, jsonb) TO service_role;
REVOKE ALL ON FUNCTION public.mark_ballot_relayed(uuid, bigint, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mark_ballot_relayed(uuid, bigint, text) TO service_role;
