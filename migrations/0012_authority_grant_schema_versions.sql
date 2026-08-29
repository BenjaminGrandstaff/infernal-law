ALTER TABLE authority_grants
    ADD COLUMN IF NOT EXISTS artifact_schema_version_id uuid,
    ADD COLUMN IF NOT EXISTS permission_policy_schema_version_id uuid;

ALTER TABLE authority_grants
    ALTER COLUMN artifact_schema_version_id SET NOT NULL,
    ALTER COLUMN permission_policy_schema_version_id SET NOT NULL;

ALTER TABLE authority_grants
    DROP CONSTRAINT IF EXISTS authority_grants_artifact_schema_version_fk,
    ADD CONSTRAINT authority_grants_artifact_schema_version_fk
        FOREIGN KEY (artifact_schema_version_id)
        REFERENCES authority_schema_versions (schema_version_id),
    DROP CONSTRAINT IF EXISTS authority_grants_permission_policy_schema_version_fk,
    ADD CONSTRAINT authority_grants_permission_policy_schema_version_fk
        FOREIGN KEY (permission_policy_schema_version_id)
        REFERENCES authority_schema_versions (schema_version_id);

DROP INDEX IF EXISTS authority_grants_match_idx;
CREATE INDEX authority_grants_match_idx
    ON authority_grants (
        source_service_id, action, destination_service_id,
        artifact_schema_version_id, permission_policy_schema_version_id
    );

DROP FUNCTION IF EXISTS create_authority_grant(
    uuid, uuid, text, text, uuid, bigint, bigint, text, text, uuid, bigint
);

CREATE OR REPLACE FUNCTION create_authority_grant(
    requested_grant_id uuid,
    requested_source_service_id uuid,
    requested_action text,
    requested_scope text,
    requested_artifact_schema_version_id uuid,
    requested_permission_policy_schema_version_id uuid,
    requested_destination_service_id uuid,
    requested_valid_from bigint,
    requested_valid_until bigint,
    requested_administrator_identity text,
    requested_reason text,
    requested_correlation_id uuid,
    requested_created_at bigint
)
RETURNS authority_grants
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    existing_by_correlation public.authority_grants%ROWTYPE;
    artifact_kind text;
    permission_policy_kind text;
    result public.authority_grants%ROWTYPE;
BEGIN
    IF requested_administrator_identity IS NULL
       OR char_length(btrim(requested_administrator_identity)) NOT BETWEEN 1 AND 200
       OR requested_reason IS NULL
       OR char_length(btrim(requested_reason)) NOT BETWEEN 1 AND 1000
       OR requested_created_at < 0 THEN
        RAISE EXCEPTION 'invalid authority grant administration metadata';
    END IF;

    SELECT kind INTO artifact_kind
    FROM public.authority_schema_versions
    WHERE schema_version_id = requested_artifact_schema_version_id;
    IF NOT FOUND OR artifact_kind <> 'artifact' THEN
        RAISE EXCEPTION 'artifact schema version % was not found or is not an artifact schema',
            requested_artifact_schema_version_id;
    END IF;

    SELECT kind INTO permission_policy_kind
    FROM public.authority_schema_versions
    WHERE schema_version_id = requested_permission_policy_schema_version_id;
    IF NOT FOUND OR permission_policy_kind <> 'permission_policy' THEN
        RAISE EXCEPTION
            'permission-policy schema version % was not found or is not a permission-policy schema',
            requested_permission_policy_schema_version_id;
    END IF;

    SELECT * INTO existing_by_correlation
    FROM public.authority_grants
    WHERE correlation_id = requested_correlation_id;
    IF FOUND THEN
        IF existing_by_correlation.grant_id <> requested_grant_id
           OR existing_by_correlation.source_service_id <> requested_source_service_id
           OR existing_by_correlation.action <> requested_action
           OR existing_by_correlation.scope <> requested_scope
           OR existing_by_correlation.artifact_schema_version_id
              <> requested_artifact_schema_version_id
           OR existing_by_correlation.permission_policy_schema_version_id
              <> requested_permission_policy_schema_version_id
           OR existing_by_correlation.destination_service_id
              IS DISTINCT FROM requested_destination_service_id
           OR existing_by_correlation.valid_from <> requested_valid_from
           OR existing_by_correlation.valid_until IS DISTINCT FROM requested_valid_until THEN
            RAISE EXCEPTION 'authority grant correlation ID conflicts with different content';
        END IF;
        RETURN existing_by_correlation;
    END IF;

    PERFORM 1 FROM public.authority_grants WHERE grant_id = requested_grant_id;
    IF FOUND THEN
        INSERT INTO public.authority_grant_administration_audit
            (grant_id, outcome, administrator_identity, reason, correlation_id, recorded_at)
        VALUES (requested_grant_id, 'create_conflict_rejected',
                btrim(requested_administrator_identity), btrim(requested_reason),
                requested_correlation_id, requested_created_at);
        RAISE EXCEPTION 'authority grant ID % already exists', requested_grant_id;
    END IF;

    INSERT INTO public.authority_grants
        (grant_id, source_service_id, action, scope,
         artifact_schema_version_id, permission_policy_schema_version_id,
         destination_service_id, valid_from, valid_until,
         administrator_identity, reason, correlation_id, created_at)
    VALUES
        (requested_grant_id, requested_source_service_id, requested_action, requested_scope,
         requested_artifact_schema_version_id, requested_permission_policy_schema_version_id,
         requested_destination_service_id, requested_valid_from, requested_valid_until,
         btrim(requested_administrator_identity), btrim(requested_reason),
         requested_correlation_id, requested_created_at)
    RETURNING * INTO result;

    INSERT INTO public.authority_grant_administration_audit
        (grant_id, outcome, administrator_identity, reason, correlation_id, recorded_at)
    VALUES (requested_grant_id, 'created',
            btrim(requested_administrator_identity), btrim(requested_reason),
            requested_correlation_id, requested_created_at);

    RETURN result;
END;
$$;

REVOKE ALL ON FUNCTION create_authority_grant(
    uuid, uuid, text, text, uuid, uuid, uuid, bigint, bigint, text, text, uuid, bigint
) FROM PUBLIC;

INSERT INTO kernel_schema_migrations (version, name)
VALUES (12, 'authority_grant_schema_versions')
ON CONFLICT (version) DO NOTHING;
