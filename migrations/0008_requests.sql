CREATE TABLE IF NOT EXISTS accepted_requests (
    source_service_id uuid NOT NULL REFERENCES identities(id),
    request_id uuid NOT NULL,
    action text NOT NULL CHECK (
        char_length(action) BETWEEN 3 AND 200
        AND action = lower(action)
        AND action ~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$'
    ),
    semantic_fingerprint bytea NOT NULL CHECK (
        octet_length(semantic_fingerprint) = 32
    ),
    accepted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (source_service_id, request_id)
);

CREATE INDEX IF NOT EXISTS accepted_requests_action_idx
    ON accepted_requests (action, accepted_at, source_service_id, request_id);

CREATE TABLE IF NOT EXISTS request_acceptance_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_service_id uuid NOT NULL,
    request_id uuid NOT NULL,
    attempted_action text NOT NULL,
    attempted_fingerprint bytea NOT NULL CHECK (
        octet_length(attempted_fingerprint) = 32
    ),
    outcome text NOT NULL CHECK (
        outcome IN ('accepted', 'safe_retry', 'request_conflict_rejected')
    ),
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (source_service_id, request_id)
        REFERENCES accepted_requests (source_service_id, request_id)
);

CREATE OR REPLACE FUNCTION reject_accepted_request_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'accepted request history is append-only';
END;
$$;

DROP TRIGGER IF EXISTS accepted_requests_append_only ON accepted_requests;
CREATE TRIGGER accepted_requests_append_only
BEFORE UPDATE OR DELETE ON accepted_requests
FOR EACH ROW EXECUTE FUNCTION reject_accepted_request_mutation();

DROP TRIGGER IF EXISTS request_acceptance_audit_append_only
    ON request_acceptance_audit;
CREATE TRIGGER request_acceptance_audit_append_only
BEFORE UPDATE OR DELETE ON request_acceptance_audit
FOR EACH ROW EXECUTE FUNCTION reject_accepted_request_mutation();

INSERT INTO kernel_schema_migrations (version, name)
VALUES (8, 'requests')
ON CONFLICT (version) DO NOTHING;
