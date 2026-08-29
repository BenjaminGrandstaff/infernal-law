CREATE TABLE IF NOT EXISTS kernel_schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE IF NOT EXISTS identities (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('service', 'worker')),
    display_name text NOT NULL CHECK (
        char_length(btrim(display_name)) BETWEEN 1 AND 200
    ),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

INSERT INTO kernel_schema_migrations (version, name)
VALUES (1, 'identities')
ON CONFLICT (version) DO NOTHING;
