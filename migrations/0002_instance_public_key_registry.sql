CREATE TABLE IF NOT EXISTS service_instances (
    instance_id uuid PRIMARY KEY,
    service_id uuid NOT NULL REFERENCES identities(id),
    endpoint text NOT NULL CHECK (
        char_length(endpoint) BETWEEN 1 AND 2048
        AND endpoint LIKE 'https://%'
    ),
    registered_at bigint NOT NULL CHECK (registered_at >= 0),
    lease_expires_at bigint NOT NULL,
    lease_revision bigint NOT NULL DEFAULT 1 CHECK (lease_revision > 0),
    revoked_at bigint,
    CHECK (lease_expires_at > registered_at),
    CHECK (revoked_at IS NULL OR revoked_at >= registered_at)
);

CREATE INDEX IF NOT EXISTS service_instances_eligible_idx
    ON service_instances (service_id, lease_expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS service_instance_keys (
    key_id uuid PRIMARY KEY,
    instance_id uuid NOT NULL UNIQUE
        REFERENCES service_instances(instance_id),
    algorithm text NOT NULL CHECK (algorithm = 'ed25519'),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    valid_from bigint NOT NULL CHECK (valid_from >= 0),
    revoked_at bigint,
    CHECK (revoked_at IS NULL OR revoked_at >= valid_from)
);

CREATE UNIQUE INDEX IF NOT EXISTS service_instance_keys_fingerprint_idx
    ON service_instance_keys (fingerprint);

CREATE TABLE IF NOT EXISTS service_instance_registry_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    key_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('registered', 'renewed', 'revoked')),
    lease_revision bigint NOT NULL CHECK (lease_revision > 0),
    recorded_at bigint NOT NULL CHECK (recorded_at >= 0)
);

CREATE OR REPLACE FUNCTION reject_instance_registry_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'service instance registry audit is append-only';
END;
$$;

DROP TRIGGER IF EXISTS service_instance_registry_audit_append_only
    ON service_instance_registry_audit;

CREATE TRIGGER service_instance_registry_audit_append_only
BEFORE UPDATE OR DELETE ON service_instance_registry_audit
FOR EACH ROW EXECUTE FUNCTION reject_instance_registry_audit_mutation();

INSERT INTO kernel_schema_migrations (version, name)
VALUES (2, 'instance_public_key_registry')
ON CONFLICT (version) DO NOTHING;
