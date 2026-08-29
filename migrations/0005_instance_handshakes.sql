CREATE TABLE IF NOT EXISTS service_instance_handshake_challenges (
    challenge_digest bytea PRIMARY KEY CHECK (octet_length(challenge_digest) = 32),
    kernel_instance_id uuid NOT NULL,
    target_instance_id uuid NOT NULL REFERENCES service_instances(instance_id),
    target_key_id uuid NOT NULL REFERENCES service_instance_keys(key_id),
    issued_at bigint NOT NULL CHECK (issued_at >= 0),
    expires_at bigint NOT NULL CHECK (expires_at > issued_at),
    consumed_at bigint,
    CHECK (consumed_at IS NULL OR consumed_at >= issued_at)
);

CREATE INDEX IF NOT EXISTS handshake_challenges_pending_idx
    ON service_instance_handshake_challenges
        (kernel_instance_id, target_instance_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS service_instance_handshakes (
    challenge_digest bytea PRIMARY KEY
        REFERENCES service_instance_handshake_challenges(challenge_digest),
    kernel_instance_id uuid NOT NULL,
    target_instance_id uuid NOT NULL REFERENCES service_instances(instance_id),
    target_key_id uuid NOT NULL REFERENCES service_instance_keys(key_id),
    verified_at bigint NOT NULL CHECK (verified_at >= 0),
    expires_at bigint NOT NULL CHECK (expires_at > verified_at)
);

CREATE INDEX IF NOT EXISTS service_instance_handshakes_fresh_idx
    ON service_instance_handshakes
        (kernel_instance_id, target_instance_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS service_instance_handshake_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    challenge_digest bytea NOT NULL CHECK (octet_length(challenge_digest) = 32),
    kernel_instance_id uuid NOT NULL,
    target_instance_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('issued', 'verified')),
    recorded_at bigint NOT NULL CHECK (recorded_at >= 0)
);

CREATE OR REPLACE FUNCTION protect_handshake_challenge_history()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'handshake challenge history cannot be deleted';
    END IF;
    IF NEW.challenge_digest <> OLD.challenge_digest
       OR NEW.kernel_instance_id <> OLD.kernel_instance_id
       OR NEW.target_instance_id <> OLD.target_instance_id
       OR NEW.target_key_id <> OLD.target_key_id
       OR NEW.issued_at <> OLD.issued_at
       OR NEW.expires_at <> OLD.expires_at
       OR OLD.consumed_at IS NOT NULL
       OR NEW.consumed_at IS NULL THEN
        RAISE EXCEPTION 'handshake challenge is immutable except for first consumption';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS handshake_challenges_protect_history
    ON service_instance_handshake_challenges;
CREATE TRIGGER handshake_challenges_protect_history
BEFORE UPDATE OR DELETE ON service_instance_handshake_challenges
FOR EACH ROW EXECUTE FUNCTION protect_handshake_challenge_history();

CREATE OR REPLACE FUNCTION reject_handshake_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'handshake history is append-only';
END;
$$;

DROP TRIGGER IF EXISTS instance_handshakes_append_only
    ON service_instance_handshakes;
CREATE TRIGGER instance_handshakes_append_only
BEFORE UPDATE OR DELETE ON service_instance_handshakes
FOR EACH ROW EXECUTE FUNCTION reject_handshake_history_mutation();

DROP TRIGGER IF EXISTS instance_handshake_audit_append_only
    ON service_instance_handshake_audit;
CREATE TRIGGER instance_handshake_audit_append_only
BEFORE UPDATE OR DELETE ON service_instance_handshake_audit
FOR EACH ROW EXECUTE FUNCTION reject_handshake_history_mutation();

INSERT INTO kernel_schema_migrations (version, name)
VALUES (5, 'instance_handshakes')
ON CONFLICT (version) DO NOTHING;
