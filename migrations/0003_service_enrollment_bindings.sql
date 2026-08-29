CREATE TABLE IF NOT EXISTS service_enrollment_bindings (
    service_id uuid PRIMARY KEY REFERENCES identities(id),
    namespace text NOT NULL CHECK (char_length(btrim(namespace)) BETWEEN 1 AND 253),
    service_account text NOT NULL CHECK (
        char_length(btrim(service_account)) BETWEEN 1 AND 253
    ),
    service_account_uid text NOT NULL CHECK (
        char_length(btrim(service_account_uid)) BETWEEN 1 AND 253
    ),
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (namespace, service_account, service_account_uid)
);

CREATE TABLE IF NOT EXISTS service_enrollment_challenges (
    challenge_digest bytea PRIMARY KEY CHECK (octet_length(challenge_digest) = 32),
    service_id uuid NOT NULL REFERENCES identities(id),
    expires_at bigint NOT NULL CHECK (expires_at >= 0),
    consumed_at bigint CHECK (consumed_at IS NULL OR consumed_at >= 0),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS service_enrollment_challenges_service_id_idx
    ON service_enrollment_challenges (service_id, expires_at)
    WHERE consumed_at IS NULL;

INSERT INTO kernel_schema_migrations (version, name)
VALUES (3, 'service_enrollment_bindings')
ON CONFLICT (version) DO NOTHING;
