CREATE TABLE public.election_ballot_chain_heads (
  election_id uuid PRIMARY KEY REFERENCES public.elections(election_id) ON DELETE RESTRICT,
  last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
  last_hash bytea NOT NULL DEFAULT pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
  CONSTRAINT election_ballot_chain_head_hash_length CHECK (octet_length(last_hash) = 32)
);

CREATE TABLE public.accepted_ballots (
  election_id uuid NOT NULL REFERENCES public.elections(election_id) ON DELETE RESTRICT,
  ballot_sequence bigint NOT NULL CHECK (ballot_sequence > 0),
  ballot_id text NOT NULL,
  ballot_hash bytea NOT NULL,
  ballot_payload jsonb NOT NULL,
  nullifier numeric(78, 0),
  accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  previous_hash bytea NOT NULL,
  record_hash bytea NOT NULL,
  PRIMARY KEY (election_id, ballot_sequence),
  CONSTRAINT accepted_ballot_id_hex_check CHECK (ballot_id ~ '^[a-f0-9]{64}$'),
  CONSTRAINT accepted_ballot_hash_length CHECK (octet_length(ballot_hash) = 32),
  CONSTRAINT accepted_ballot_payload_object CHECK (jsonb_typeof(ballot_payload) = 'object'),
  CONSTRAINT accepted_ballot_nullifier_range CHECK (nullifier IS NULL OR nullifier >= 0),
  CONSTRAINT accepted_ballot_previous_hash_length CHECK (octet_length(previous_hash) = 32),
  CONSTRAINT accepted_ballot_record_hash_length CHECK (octet_length(record_hash) = 32),
  CONSTRAINT accepted_ballot_unique_digest UNIQUE (election_id, ballot_hash),
  CONSTRAINT accepted_ballot_unique_id UNIQUE (election_id, ballot_id),
  CONSTRAINT accepted_ballot_unique_nullifier UNIQUE (election_id, nullifier)
);

CREATE INDEX accepted_ballots_public_tally_idx
  ON public.accepted_ballots (election_id, ballot_sequence);

ALTER TABLE public.accepted_ballots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.election_ballot_chain_heads ENABLE ROW LEVEL SECURITY;

GRANT SELECT ON TABLE public.accepted_ballots TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.election_ballot_chain_heads TO service_role;
GRANT SELECT, INSERT ON TABLE public.accepted_ballots TO service_role;

CREATE POLICY published_election_ballots_are_readable
  ON public.accepted_ballots FOR SELECT
  TO anon, authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.elections election
      WHERE election.election_id = accepted_ballots.election_id
        AND election.status <> 'draft'
    )
  );

CREATE OR REPLACE FUNCTION public.accepted_ballots_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $function$
BEGIN
  RAISE EXCEPTION 'Accepted ballots are append-only';
END;
$function$;

CREATE TRIGGER accepted_ballots_reject_update_delete
  BEFORE UPDATE OR DELETE ON public.accepted_ballots
  FOR EACH ROW EXECUTE FUNCTION public.accepted_ballots_reject_mutation();

CREATE OR REPLACE FUNCTION public.record_accepted_ballot(
  p_election_id uuid,
  p_ballot_id text,
  p_ballot_hash_hex text,
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
  accepted_timestamp timestamptz;
BEGIN
  IF p_ballot_id !~ '^[a-f0-9]{64}$' OR p_ballot_hash_hex !~ '^[a-f0-9]{64}$' OR
      pg_catalog.jsonb_typeof(p_ballot_payload) <> 'object' THEN
    RAISE EXCEPTION 'Invalid accepted ballot payload';
  END IF;

  SELECT election_id, status, starts_at, ends_at
    INTO election_row
    FROM public.elections
    WHERE election_id = p_election_id
    FOR SHARE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false);
  END IF;
  IF election_row.status <> 'active' OR pg_catalog.clock_timestamp() < election_row.starts_at OR
      pg_catalog.clock_timestamp() >= election_row.ends_at THEN
    RETURN pg_catalog.jsonb_build_object('found', true, 'open', false);
  END IF;

  INSERT INTO public.election_ballot_chain_heads (election_id)
    VALUES (p_election_id) ON CONFLICT (election_id) DO NOTHING;
  SELECT last_sequence, last_hash
    INTO next_sequence, previous_hash
    FROM public.election_ballot_chain_heads
    WHERE election_id = p_election_id
    FOR UPDATE;

  next_sequence := next_sequence + 1;
  ballot_hash_bytes := pg_catalog.decode(p_ballot_hash_hex, 'hex');
  accepted_timestamp := pg_catalog.clock_timestamp();
  record_hash_bytes := extensions.digest(
    pg_catalog.uuid_send(p_election_id) ||
    pg_catalog.int8send(next_sequence) ||
    previous_hash ||
    ballot_hash_bytes,
    'sha256'
  );

  BEGIN
    INSERT INTO public.accepted_ballots (
      election_id, ballot_sequence, ballot_id, ballot_hash, ballot_payload,
      accepted_at, previous_hash, record_hash
    ) VALUES (
      p_election_id, next_sequence, p_ballot_id, ballot_hash_bytes, p_ballot_payload,
      accepted_timestamp, previous_hash, record_hash_bytes
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

REVOKE ALL ON FUNCTION public.record_accepted_ballot(uuid, text, text, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_accepted_ballot(uuid, text, text, jsonb) TO service_role;
REVOKE ALL ON FUNCTION public.accepted_ballots_reject_mutation() FROM PUBLIC, anon, authenticated, service_role;
