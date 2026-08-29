CREATE TABLE IF NOT EXISTS authority_schema_versions (
    schema_version_id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('artifact', 'permission_policy')),
    name text NOT NULL CHECK (
        char_length(name) BETWEEN 3 AND 200
        AND name = lower(name)
        AND name ~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$'
    ),
    version bigint NOT NULL CHECK (version >= 1),
    owner_service_id uuid NOT NULL REFERENCES identities(id),
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    predecessor_id uuid REFERENCES authority_schema_versions(schema_version_id),
    published_at bigint NOT NULL CHECK (published_at >= 0),
    status text NOT NULL DEFAULT 'published' CHECK (
        status IN ('published', 'active', 'suspended', 'superseded', 'retired')
    ),
    UNIQUE (kind, name, version)
);

CREATE INDEX IF NOT EXISTS authority_schema_versions_lookup_idx
    ON authority_schema_versions (kind, name, version);

CREATE OR REPLACE FUNCTION protect_authority_schema_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'authority schema versions cannot be deleted';
    END IF;
    IF current_setting('infernal_law.schema_status_change_context', true) IS NULL
       OR current_setting('infernal_law.schema_status_change_context', true) = '' THEN
        RAISE EXCEPTION 'authority schema status changes require the administrative function';
    END IF;
    IF NEW.schema_version_id <> OLD.schema_version_id
       OR NEW.kind <> OLD.kind
       OR NEW.name <> OLD.name
       OR NEW.version <> OLD.version
       OR NEW.owner_service_id <> OLD.owner_service_id
       OR NEW.content_digest <> OLD.content_digest
       OR NEW.predecessor_id IS DISTINCT FROM OLD.predecessor_id
       OR NEW.published_at <> OLD.published_at THEN
        RAISE EXCEPTION 'only status may change on an authority schema version';
    END IF;
    IF OLD.status IN ('superseded', 'retired') THEN
        RAISE EXCEPTION 'authority schema version status % is terminal', OLD.status;
    END IF;
    IF NEW.status = OLD.status THEN
        RAISE EXCEPTION 'authority schema status transition must change the status';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS authority_schema_versions_protect ON authority_schema_versions;
CREATE TRIGGER authority_schema_versions_protect
BEFORE UPDATE OR DELETE ON authority_schema_versions
FOR EACH ROW EXECUTE FUNCTION protect_authority_schema_version();

CREATE TABLE IF NOT EXISTS authority_schema_status_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    schema_version_id uuid NOT NULL,
    old_status text,
    new_status text NOT NULL,
    outcome text NOT NULL CHECK (
        outcome IN ('changed', 'no_op', 'rejected_terminal', 'rejected_unknown_schema')
    ),
    administrator_identity text NOT NULL CHECK (
        char_length(btrim(administrator_identity)) BETWEEN 1 AND 200
    ),
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    correlation_id uuid NOT NULL,
    recorded_at bigint NOT NULL CHECK (recorded_at >= 0),
    UNIQUE (schema_version_id, correlation_id)
);

CREATE OR REPLACE FUNCTION reject_authority_schema_status_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authority schema status audit is append-only';
END;
$$;

DROP TRIGGER IF EXISTS authority_schema_status_audit_append_only
    ON authority_schema_status_audit;
CREATE TRIGGER authority_schema_status_audit_append_only
BEFORE UPDATE OR DELETE ON authority_schema_status_audit
FOR EACH ROW EXECUTE FUNCTION reject_authority_schema_status_audit_mutation();

CREATE OR REPLACE FUNCTION publish_authority_schema_version(
    requested_schema_version_id uuid,
    requested_kind text,
    requested_name text,
    requested_owner_service_id uuid,
    requested_content_digest bytea,
    requested_published_at bigint
)
RETURNS authority_schema_versions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    latest public.authority_schema_versions%ROWTYPE;
    has_latest boolean;
    next_version bigint;
    predecessor uuid;
    result public.authority_schema_versions%ROWTYPE;
BEGIN
    SELECT * INTO latest
    FROM public.authority_schema_versions
    WHERE kind = requested_kind AND name = requested_name
    ORDER BY version DESC
    LIMIT 1
    FOR UPDATE;
    has_latest := FOUND;

    IF has_latest THEN
        IF latest.owner_service_id <> requested_owner_service_id THEN
            RAISE EXCEPTION 'schema name % is owned by a different service', requested_name;
        END IF;
        next_version := latest.version + 1;
        predecessor := latest.schema_version_id;
    ELSE
        next_version := 1;
        predecessor := NULL;
    END IF;

    INSERT INTO public.authority_schema_versions
        (schema_version_id, kind, name, version, owner_service_id, content_digest,
         predecessor_id, published_at)
    VALUES
        (requested_schema_version_id, requested_kind, requested_name, next_version,
         requested_owner_service_id, requested_content_digest,
         predecessor, requested_published_at)
    RETURNING * INTO result;

    RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION set_authority_schema_status(
    requested_schema_version_id uuid,
    requested_status text,
    requested_administrator_identity text,
    requested_reason text,
    requested_correlation_id uuid,
    requested_changed_at bigint
)
RETURNS TABLE (
    result_status text,
    result_changed_at bigint,
    result_outcome text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    existing_audit public.authority_schema_status_audit%ROWTYPE;
    current_schema public.authority_schema_versions%ROWTYPE;
BEGIN
    IF requested_administrator_identity IS NULL
       OR char_length(btrim(requested_administrator_identity)) NOT BETWEEN 1 AND 200
       OR requested_reason IS NULL
       OR char_length(btrim(requested_reason)) NOT BETWEEN 1 AND 1000
       OR requested_changed_at < 0
       OR requested_status NOT IN ('active', 'suspended', 'superseded', 'retired') THEN
        RAISE EXCEPTION 'invalid authority schema status administration metadata';
    END IF;

    SELECT * INTO existing_audit
    FROM public.authority_schema_status_audit
    WHERE schema_version_id = requested_schema_version_id
      AND correlation_id = requested_correlation_id;
    IF FOUND THEN
        IF existing_audit.new_status <> requested_status THEN
            RAISE EXCEPTION 'authority schema status correlation ID conflicts with a different status';
        END IF;
        RETURN QUERY SELECT existing_audit.new_status, existing_audit.recorded_at,
            existing_audit.outcome;
        RETURN;
    END IF;

    SELECT * INTO current_schema
    FROM public.authority_schema_versions
    WHERE schema_version_id = requested_schema_version_id
    FOR UPDATE;
    IF NOT FOUND THEN
        INSERT INTO public.authority_schema_status_audit
            (schema_version_id, old_status, new_status, outcome,
             administrator_identity, reason, correlation_id, recorded_at)
        VALUES
            (requested_schema_version_id, NULL, requested_status, 'rejected_unknown_schema',
             btrim(requested_administrator_identity), btrim(requested_reason),
             requested_correlation_id, requested_changed_at);
        RAISE EXCEPTION 'authority schema version was not found';
    END IF;

    IF current_schema.status IN ('superseded', 'retired') THEN
        INSERT INTO public.authority_schema_status_audit
            (schema_version_id, old_status, new_status, outcome,
             administrator_identity, reason, correlation_id, recorded_at)
        VALUES
            (requested_schema_version_id, current_schema.status, requested_status,
             'rejected_terminal', btrim(requested_administrator_identity),
             btrim(requested_reason), requested_correlation_id, requested_changed_at);
        RAISE EXCEPTION 'authority schema version status % is terminal', current_schema.status;
    END IF;

    IF current_schema.status = requested_status THEN
        INSERT INTO public.authority_schema_status_audit
            (schema_version_id, old_status, new_status, outcome,
             administrator_identity, reason, correlation_id, recorded_at)
        VALUES
            (requested_schema_version_id, current_schema.status, requested_status, 'no_op',
             btrim(requested_administrator_identity), btrim(requested_reason),
             requested_correlation_id, requested_changed_at);
        RETURN QUERY SELECT requested_status, requested_changed_at, 'no_op'::text;
        RETURN;
    END IF;

    PERFORM set_config(
        'infernal_law.schema_status_change_context',
        requested_correlation_id::text,
        true
    );
    UPDATE public.authority_schema_versions
    SET status = requested_status
    WHERE schema_version_id = requested_schema_version_id;
    PERFORM set_config('infernal_law.schema_status_change_context', '', true);

    INSERT INTO public.authority_schema_status_audit
        (schema_version_id, old_status, new_status, outcome,
         administrator_identity, reason, correlation_id, recorded_at)
    VALUES
        (requested_schema_version_id, current_schema.status, requested_status, 'changed',
         btrim(requested_administrator_identity), btrim(requested_reason),
         requested_correlation_id, requested_changed_at);

    RETURN QUERY SELECT requested_status, requested_changed_at, 'changed'::text;
END;
$$;

REVOKE ALL ON FUNCTION set_authority_schema_status(
    uuid, text, text, text, uuid, bigint
) FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON authority_schema_versions FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON authority_schema_status_audit FROM PUBLIC;

INSERT INTO kernel_schema_migrations (version, name)
VALUES (10, 'authority_schema_versions')
ON CONFLICT (version) DO NOTHING;
