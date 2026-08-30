ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS delivery_mode text;

ALTER TABLE subscriptions
    ALTER COLUMN delivery_mode SET NOT NULL;

ALTER TABLE subscriptions
    DROP CONSTRAINT IF EXISTS subscriptions_delivery_mode_check,
    ADD CONSTRAINT subscriptions_delivery_mode_check CHECK (delivery_mode IN ('inclusive'));

ALTER TABLE subscription_audit
    ADD COLUMN IF NOT EXISTS delivery_mode text;

ALTER TABLE subscription_audit
    ALTER COLUMN delivery_mode SET NOT NULL;

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
       OR NEW.delivery_mode <> OLD.delivery_mode
       OR NEW.created_at <> OLD.created_at
       OR OLD.disabled_at IS NOT NULL
       OR NEW.disabled_at IS NULL THEN
        RAISE EXCEPTION 'subscription history is immutable except for first disable';
    END IF;
    RETURN NEW;
END;
$$;

INSERT INTO kernel_schema_migrations (version, name)
VALUES (15, 'subscription_delivery_modes')
ON CONFLICT (version) DO NOTHING;
