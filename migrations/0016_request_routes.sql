CREATE TABLE IF NOT EXISTS request_routes (
    route_id uuid PRIMARY KEY,
    source_service_id uuid NOT NULL,
    request_id uuid NOT NULL,
    subscription_id uuid NOT NULL REFERENCES subscriptions (id),
    destination_service_id uuid NOT NULL REFERENCES identities (id),
    created_at bigint NOT NULL CHECK (created_at >= 0),
    UNIQUE (request_id, subscription_id),
    CONSTRAINT request_routes_accepted_request_fk
        FOREIGN KEY (source_service_id, request_id)
        REFERENCES accepted_requests (source_service_id, request_id)
);

CREATE INDEX IF NOT EXISTS request_routes_request_idx
    ON request_routes (request_id);

CREATE OR REPLACE FUNCTION reject_request_route_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'request routes are append-only';
END;
$$;

DROP TRIGGER IF EXISTS request_routes_append_only ON request_routes;
CREATE TRIGGER request_routes_append_only
BEFORE UPDATE OR DELETE ON request_routes
FOR EACH ROW EXECUTE FUNCTION reject_request_route_mutation();

INSERT INTO kernel_schema_migrations (version, name)
VALUES (16, 'request_routes')
ON CONFLICT (version) DO NOTHING;
