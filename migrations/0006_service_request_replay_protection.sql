CREATE TABLE IF NOT EXISTS service_request_ids (
    service_id uuid NOT NULL REFERENCES identities(id),
    request_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    first_seen_at bigint NOT NULL CHECK (first_seen_at >= 0),
    PRIMARY KEY (service_id, request_id)
);

CREATE TABLE IF NOT EXISTS service_request_nonces (
    key_id uuid NOT NULL REFERENCES service_instance_keys(key_id),
    nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest) = 32),
    service_id uuid NOT NULL REFERENCES identities(id),
    instance_id uuid NOT NULL REFERENCES service_instances(instance_id),
    request_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    signature_created bigint NOT NULL CHECK (signature_created >= 0),
    signature_expires bigint NOT NULL,
    reserved_at bigint NOT NULL CHECK (reserved_at >= 0),
    CHECK (signature_expires > signature_created),
    PRIMARY KEY (key_id, nonce_digest)
);

CREATE INDEX IF NOT EXISTS service_request_nonces_request_idx
    ON service_request_nonces (service_id, request_id, reserved_at);

CREATE TABLE IF NOT EXISTS service_request_replay_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    key_id uuid NOT NULL,
    request_id uuid NOT NULL,
    nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest) = 32),
    request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    outcome text NOT NULL CHECK (
        outcome IN ('fresh', 'safe_retry', 'replay_rejected', 'request_conflict_rejected')
    ),
    recorded_at bigint NOT NULL CHECK (recorded_at >= 0)
);

CREATE OR REPLACE FUNCTION reject_service_request_replay_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'service request replay history is append-only';
END;
$$;

DROP TRIGGER IF EXISTS service_request_ids_append_only ON service_request_ids;
CREATE TRIGGER service_request_ids_append_only
BEFORE UPDATE OR DELETE ON service_request_ids
FOR EACH ROW EXECUTE FUNCTION reject_service_request_replay_mutation();

DROP TRIGGER IF EXISTS service_request_nonces_append_only ON service_request_nonces;
CREATE TRIGGER service_request_nonces_append_only
BEFORE UPDATE OR DELETE ON service_request_nonces
FOR EACH ROW EXECUTE FUNCTION reject_service_request_replay_mutation();

DROP TRIGGER IF EXISTS service_request_replay_audit_append_only
    ON service_request_replay_audit;
CREATE TRIGGER service_request_replay_audit_append_only
BEFORE UPDATE OR DELETE ON service_request_replay_audit
FOR EACH ROW EXECUTE FUNCTION reject_service_request_replay_mutation();

INSERT INTO kernel_schema_migrations (version, name)
VALUES (6, 'service_request_replay_protection')
ON CONFLICT (version) DO NOTHING;
