ALTER TABLE accepted_requests
    ADD COLUMN IF NOT EXISTS scope text,
    ADD COLUMN IF NOT EXISTS artifact_schema_version_id uuid,
    ADD COLUMN IF NOT EXISTS permission_policy_schema_version_id uuid;

ALTER TABLE accepted_requests
    ALTER COLUMN scope SET NOT NULL,
    ALTER COLUMN artifact_schema_version_id SET NOT NULL,
    ALTER COLUMN permission_policy_schema_version_id SET NOT NULL;

ALTER TABLE accepted_requests
    DROP CONSTRAINT IF EXISTS accepted_requests_scope_check,
    ADD CONSTRAINT accepted_requests_scope_check CHECK (
        char_length(scope) BETWEEN 1 AND 200 AND scope = btrim(scope)
    );

ALTER TABLE accepted_requests
    DROP CONSTRAINT IF EXISTS accepted_requests_artifact_schema_version_fk,
    ADD CONSTRAINT accepted_requests_artifact_schema_version_fk
        FOREIGN KEY (artifact_schema_version_id)
        REFERENCES authority_schema_versions (schema_version_id),
    DROP CONSTRAINT IF EXISTS accepted_requests_permission_policy_schema_version_fk,
    ADD CONSTRAINT accepted_requests_permission_policy_schema_version_fk
        FOREIGN KEY (permission_policy_schema_version_id)
        REFERENCES authority_schema_versions (schema_version_id);

ALTER TABLE request_acceptance_audit
    ADD COLUMN IF NOT EXISTS attempted_scope text,
    ADD COLUMN IF NOT EXISTS attempted_artifact_schema_version_id uuid,
    ADD COLUMN IF NOT EXISTS attempted_permission_policy_schema_version_id uuid;

ALTER TABLE request_acceptance_audit
    ALTER COLUMN attempted_scope SET NOT NULL,
    ALTER COLUMN attempted_artifact_schema_version_id SET NOT NULL,
    ALTER COLUMN attempted_permission_policy_schema_version_id SET NOT NULL;

INSERT INTO kernel_schema_migrations (version, name)
VALUES (14, 'request_schema_versions')
ON CONFLICT (version) DO NOTHING;
