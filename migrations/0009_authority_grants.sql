CREATE TABLE IF NOT EXISTS authority_grants (
    grant_id uuid PRIMARY KEY,
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
    valid_from bigint NOT NULL CHECK (valid_from >= 0),
    valid_until bigint CHECK (valid_until IS NULL OR valid_until > valid_from),
    administrator_identity text NOT NULL CHECK (
        char_length(btrim(administrator_identity)) BETWEEN 1 AND 200
    ),
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    correlation_id uuid NOT NULL UNIQUE,
    created_at bigint NOT NULL CHECK (created_at >= 0)
);

CREATE INDEX IF NOT EXISTS authority_grants_match_idx
    ON authority_grants (source_service_id, action, destination_service_id);

CREATE OR REPLACE FUNCTION reject_authority_grant_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authority grants are append-only';
END;
$$;

DROP TRIGGER IF EXISTS authority_grants_append_only ON authority_grants;
CREATE TRIGGER authority_grants_append_only
BEFORE UPDATE OR DELETE ON authority_grants
FOR EACH ROW EXECUTE FUNCTION reject_authority_grant_mutation();

CREATE TABLE IF NOT EXISTS authority_grant_administration_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    grant_id uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('created', 'create_conflict_rejected')),
    administrator_identity text NOT NULL CHECK (
        char_length(btrim(administrator_identity)) BETWEEN 1 AND 200
    ),
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    correlation_id uuid NOT NULL,
    recorded_at bigint NOT NULL CHECK (recorded_at >= 0)
);

CREATE OR REPLACE FUNCTION reject_authority_grant_administration_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authority grant administration audit is append-only';
END;
$$;

DROP TRIGGER IF EXISTS authority_grant_administration_audit_append_only
    ON authority_grant_administration_audit;
CREATE TRIGGER authority_grant_administration_audit_append_only
BEFORE UPDATE OR DELETE ON authority_grant_administration_audit
FOR EACH ROW EXECUTE FUNCTION reject_authority_grant_administration_audit_mutation();

CREATE OR REPLACE FUNCTION create_authority_grant(
    requested_grant_id uuid,
    requested_source_service_id uuid,
    requested_action text,
    requested_scope text,
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
    result public.authority_grants%ROWTYPE;
BEGIN
    IF requested_administrator_identity IS NULL
       OR char_length(btrim(requested_administrator_identity)) NOT BETWEEN 1 AND 200
       OR requested_reason IS NULL
       OR char_length(btrim(requested_reason)) NOT BETWEEN 1 AND 1000
       OR requested_created_at < 0 THEN
        RAISE EXCEPTION 'invalid authority grant administration metadata';
    END IF;

    SELECT * INTO existing_by_correlation
    FROM public.authority_grants
    WHERE correlation_id = requested_correlation_id;
    IF FOUND THEN
        IF existing_by_correlation.grant_id <> requested_grant_id
           OR existing_by_correlation.source_service_id <> requested_source_service_id
           OR existing_by_correlation.action <> requested_action
           OR existing_by_correlation.scope <> requested_scope
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
        (grant_id, source_service_id, action, scope, destination_service_id,
         valid_from, valid_until, administrator_identity, reason, correlation_id, created_at)
    VALUES
        (requested_grant_id, requested_source_service_id, requested_action, requested_scope,
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
    uuid, uuid, text, text, uuid, bigint, bigint, text, text, uuid, bigint
) FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON authority_grants FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON authority_grant_administration_audit FROM PUBLIC;

INSERT INTO kernel_schema_migrations (version, name)
VALUES (9, 'authority_grants')
ON CONFLICT (version) DO NOTHING;
