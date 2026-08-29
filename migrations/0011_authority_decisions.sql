CREATE TABLE IF NOT EXISTS authority_decisions (
    decision_id uuid PRIMARY KEY,
    source_service_id uuid NOT NULL REFERENCES identities(id),
    action text NOT NULL CHECK (
        char_length(action) BETWEEN 3 AND 200
        AND action = lower(action)
        AND action ~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$'
    ),
    scope text NOT NULL CHECK (
        char_length(scope) BETWEEN 1 AND 200 AND scope = btrim(scope)
    ),
    destination_service_id uuid REFERENCES identities(id),
    verdict text NOT NULL CHECK (verdict IN ('allow', 'deny')),
    evaluator_service_id uuid NOT NULL REFERENCES identities(id),
    policy_bundle_version text,
    decided_at bigint NOT NULL CHECK (decided_at >= 0)
);

CREATE INDEX IF NOT EXISTS authority_decisions_lookup_idx
    ON authority_decisions (source_service_id, action, decided_at);

CREATE OR REPLACE FUNCTION reject_authority_decision_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authority decisions are append-only';
END;
$$;

DROP TRIGGER IF EXISTS authority_decisions_append_only ON authority_decisions;
CREATE TRIGGER authority_decisions_append_only
BEFORE UPDATE OR DELETE ON authority_decisions
FOR EACH ROW EXECUTE FUNCTION reject_authority_decision_mutation();

INSERT INTO kernel_schema_migrations (version, name)
VALUES (11, 'authority_decisions')
ON CONFLICT (version) DO NOTHING;
