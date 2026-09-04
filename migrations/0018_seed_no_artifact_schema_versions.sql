-- Seeds the two sentinel schema versions that `no_artifact_schema_versions()`
-- in src/kernel/authority.rs returns for every governed action that carries
-- no artifact -- subscription create/disable among them.
--
-- Without these rows, `authority_decisions` cannot be written at all for such
-- an action: its artifact and permission-policy schema version columns are
-- NOT NULL and carry foreign keys into this table, so recording the decision
-- fails and the caller sees a fail-closed 503 that looks like an unreachable
-- evaluator rather than missing seed data. That made every non-artifact
-- governed action permanently unauthorizable on a fresh database.
--
-- The sentinels are owned by a reserved nil-UUID identity rather than by the
-- kernel's own service ID, which is configurable through
-- INFERNAL_LAW_SERVICE_ID and so is not knowable from a migration. The nil
-- UUID cannot collide with a generated v4 service ID.
INSERT INTO identities (id, kind, display_name, status)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'service',
    'reserved: kernel schema registry',
    'active'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO authority_schema_versions (
    schema_version_id,
    kind,
    name,
    version,
    owner_service_id,
    content_digest,
    published_at,
    status
)
VALUES
    (
        '00000000-0000-0000-0000-000000000001',
        'artifact',
        'kernel.no-artifact',
        1,
        '00000000-0000-0000-0000-000000000000',
        sha256('kernel.no-artifact'::bytea),
        0,
        'active'
    ),
    (
        '00000000-0000-0000-0000-000000000002',
        'permission_policy',
        'kernel.no-artifact-permission-policy',
        1,
        '00000000-0000-0000-0000-000000000000',
        sha256('kernel.no-artifact-permission-policy'::bytea),
        0,
        'active'
    )
ON CONFLICT (schema_version_id) DO NOTHING;

INSERT INTO kernel_schema_migrations (version, name)
VALUES (18, 'seed_no_artifact_schema_versions')
ON CONFLICT (version) DO NOTHING;
