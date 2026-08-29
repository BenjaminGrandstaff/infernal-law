CREATE TABLE IF NOT EXISTS service_communication_admission (
    service_id uuid PRIMARY KEY REFERENCES identities(id),
    communication_enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_at bigint NOT NULL CHECK (updated_at >= 0)
);

INSERT INTO service_communication_admission (service_id, updated_at)
SELECT id, extract(epoch FROM transaction_timestamp())::bigint
FROM identities
ON CONFLICT (service_id) DO NOTHING;

CREATE OR REPLACE FUNCTION initialize_service_communication_admission()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO service_communication_admission (service_id, updated_at)
    VALUES (NEW.id, extract(epoch FROM transaction_timestamp())::bigint);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS identities_initialize_communication_admission ON identities;
CREATE TRIGGER identities_initialize_communication_admission
AFTER INSERT ON identities
FOR EACH ROW EXECUTE FUNCTION initialize_service_communication_admission();

CREATE TABLE IF NOT EXISTS service_communication_admission_history (
    history_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service_id uuid NOT NULL,
    old_enabled boolean NOT NULL,
    new_enabled boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 0),
    outcome text NOT NULL CHECK (outcome IN ('changed', 'no_op')),
    administrator_identity text NOT NULL CHECK (
        char_length(btrim(administrator_identity)) BETWEEN 1 AND 200
    ),
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    correlation_id uuid NOT NULL,
    committed_at bigint NOT NULL CHECK (committed_at >= 0),
    UNIQUE (service_id, correlation_id)
);

CREATE INDEX IF NOT EXISTS service_communication_admission_history_idx
    ON service_communication_admission_history (service_id, committed_at, history_id);

CREATE OR REPLACE FUNCTION protect_service_communication_admission()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'communication admission records cannot be deleted';
    END IF;
    IF current_setting('infernal_law.admission_change_context', true) IS NULL
       OR current_setting('infernal_law.admission_change_context', true) = '' THEN
        RAISE EXCEPTION 'communication admission changes require the administrative function';
    END IF;
    IF NEW.service_id <> OLD.service_id
       OR NEW.revision <> OLD.revision + 1
       OR NEW.communication_enabled = OLD.communication_enabled
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid communication admission state transition';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS service_communication_admission_protect
    ON service_communication_admission;
CREATE TRIGGER service_communication_admission_protect
BEFORE UPDATE OR DELETE ON service_communication_admission
FOR EACH ROW EXECUTE FUNCTION protect_service_communication_admission();

CREATE OR REPLACE FUNCTION reject_communication_admission_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'communication admission history is append-only';
END;
$$;

DROP TRIGGER IF EXISTS service_communication_admission_history_append_only
    ON service_communication_admission_history;
CREATE TRIGGER service_communication_admission_history_append_only
BEFORE UPDATE OR DELETE ON service_communication_admission_history
FOR EACH ROW EXECUTE FUNCTION reject_communication_admission_history_mutation();

CREATE OR REPLACE FUNCTION set_service_communication_admission(
    requested_service_id uuid,
    requested_enabled boolean,
    requested_administrator_identity text,
    requested_reason text,
    requested_correlation_id uuid,
    requested_changed_at bigint
)
RETURNS TABLE (
    result_enabled boolean,
    result_revision bigint,
    result_changed_at bigint,
    result_outcome text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    existing_history public.service_communication_admission_history%ROWTYPE;
    current_admission public.service_communication_admission%ROWTYPE;
    next_revision bigint;
    change_outcome text;
BEGIN
    IF requested_administrator_identity IS NULL
       OR char_length(btrim(requested_administrator_identity)) NOT BETWEEN 1 AND 200
       OR requested_reason IS NULL
       OR char_length(btrim(requested_reason)) NOT BETWEEN 1 AND 1000
       OR requested_changed_at < 0 THEN
        RAISE EXCEPTION 'invalid communication admission administration metadata';
    END IF;

    SELECT * INTO current_admission
    FROM public.service_communication_admission
    WHERE service_id = requested_service_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'service communication admission was not found';
    END IF;

    SELECT * INTO existing_history
    FROM public.service_communication_admission_history
    WHERE service_id = requested_service_id
      AND correlation_id = requested_correlation_id;
    IF FOUND THEN
        IF existing_history.new_enabled <> requested_enabled
           OR existing_history.administrator_identity <> btrim(requested_administrator_identity)
           OR existing_history.reason <> btrim(requested_reason)
           OR existing_history.committed_at <> requested_changed_at THEN
            RAISE EXCEPTION 'communication admission correlation ID conflicts';
        END IF;
        RETURN QUERY SELECT existing_history.new_enabled,
            existing_history.revision,
            existing_history.committed_at,
            existing_history.outcome;
        RETURN;
    END IF;

    IF requested_changed_at < current_admission.updated_at THEN
        RAISE EXCEPTION 'communication admission timestamp precedes current state';
    END IF;

    IF current_admission.communication_enabled = requested_enabled THEN
        next_revision := current_admission.revision;
        change_outcome := 'no_op';
    ELSE
        next_revision := current_admission.revision + 1;
        change_outcome := 'changed';
        PERFORM set_config(
            'infernal_law.admission_change_context',
            requested_correlation_id::text,
            true
        );
        UPDATE public.service_communication_admission
        SET communication_enabled = requested_enabled,
            revision = next_revision,
            updated_at = requested_changed_at
        WHERE service_id = requested_service_id;
        PERFORM set_config('infernal_law.admission_change_context', '', true);
    END IF;

    INSERT INTO public.service_communication_admission_history
        (service_id, old_enabled, new_enabled, revision, outcome,
         administrator_identity, reason, correlation_id, committed_at)
    VALUES
        (requested_service_id, current_admission.communication_enabled,
         requested_enabled, next_revision, change_outcome,
         btrim(requested_administrator_identity), btrim(requested_reason),
         requested_correlation_id, requested_changed_at);

    RETURN QUERY SELECT requested_enabled, next_revision,
        requested_changed_at, change_outcome;
END;
$$;

REVOKE ALL ON FUNCTION set_service_communication_admission(
    uuid, boolean, text, text, uuid, bigint
) FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON service_communication_admission FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON service_communication_admission_history FROM PUBLIC;

INSERT INTO kernel_schema_migrations (version, name)
VALUES (7, 'communication_admission')
ON CONFLICT (version) DO NOTHING;
