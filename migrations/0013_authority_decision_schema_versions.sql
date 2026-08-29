ALTER TABLE authority_decisions
    ADD COLUMN IF NOT EXISTS artifact_schema_version_id uuid,
    ADD COLUMN IF NOT EXISTS permission_policy_schema_version_id uuid;

ALTER TABLE authority_decisions
    ALTER COLUMN artifact_schema_version_id SET NOT NULL,
    ALTER COLUMN permission_policy_schema_version_id SET NOT NULL;

ALTER TABLE authority_decisions
    DROP CONSTRAINT IF EXISTS authority_decisions_artifact_schema_version_fk,
    ADD CONSTRAINT authority_decisions_artifact_schema_version_fk
        FOREIGN KEY (artifact_schema_version_id)
        REFERENCES authority_schema_versions (schema_version_id),
    DROP CONSTRAINT IF EXISTS authority_decisions_permission_policy_schema_version_fk,
    ADD CONSTRAINT authority_decisions_permission_policy_schema_version_fk
        FOREIGN KEY (permission_policy_schema_version_id)
        REFERENCES authority_schema_versions (schema_version_id);

INSERT INTO kernel_schema_migrations (version, name)
VALUES (13, 'authority_decision_schema_versions')
ON CONFLICT (version) DO NOTHING;
