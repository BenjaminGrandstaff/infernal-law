CREATE TABLE IF NOT EXISTS subscriptions (
    id uuid PRIMARY KEY,
    service_id uuid NOT NULL REFERENCES identities(id),
    event_type text NOT NULL CHECK (
        char_length(event_type) BETWEEN 1 AND 200
        AND event_type = lower(event_type)
        AND event_type ~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
    ),
    created_at bigint NOT NULL CHECK (created_at >= 0),
    disabled_at bigint,
    CHECK (disabled_at IS NULL OR disabled_at >= created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS subscriptions_one_active_event_idx
    ON subscriptions (service_id, event_type)
    WHERE disabled_at IS NULL;

CREATE INDEX IF NOT EXISTS subscriptions_service_history_idx
    ON subscriptions (service_id, created_at, id);

CREATE TABLE IF NOT EXISTS subscription_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subscription_id uuid NOT NULL,
    service_id uuid NOT NULL,
    event_type text NOT NULL,
    action text NOT NULL CHECK (action IN ('created', 'disabled')),
    recorded_at bigint NOT NULL CHECK (recorded_at >= 0)
);

CREATE OR REPLACE FUNCTION protect_subscription_history()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'subscription history cannot be deleted';
    END IF;
    IF NEW.id <> OLD.id
       OR NEW.service_id <> OLD.service_id
       OR NEW.event_type <> OLD.event_type
       OR NEW.created_at <> OLD.created_at
       OR OLD.disabled_at IS NOT NULL
       OR NEW.disabled_at IS NULL THEN
        RAISE EXCEPTION 'subscription history is immutable except for first disable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS subscriptions_protect_history ON subscriptions;
CREATE TRIGGER subscriptions_protect_history
BEFORE UPDATE OR DELETE ON subscriptions
FOR EACH ROW EXECUTE FUNCTION protect_subscription_history();

CREATE OR REPLACE FUNCTION reject_subscription_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'subscription audit is append-only';
END;
$$;

DROP TRIGGER IF EXISTS subscription_audit_append_only ON subscription_audit;
CREATE TRIGGER subscription_audit_append_only
BEFORE UPDATE OR DELETE ON subscription_audit
FOR EACH ROW EXECUTE FUNCTION reject_subscription_audit_mutation();

INSERT INTO kernel_schema_migrations (version, name)
VALUES (4, 'subscriptions')
ON CONFLICT (version) DO NOTHING;
