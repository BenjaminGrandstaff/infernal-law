CREATE TABLE IF NOT EXISTS work_claims (
    claim_id uuid PRIMARY KEY,
    route_id uuid NOT NULL REFERENCES request_routes (route_id),
    worker_service_id uuid NOT NULL REFERENCES identities (id),
    worker_instance_id uuid NOT NULL REFERENCES service_instances (instance_id),
    fencing_token bigint NOT NULL CHECK (fencing_token >= 1),
    status text NOT NULL CHECK (status IN ('active', 'completed', 'released', 'expired')),
    claimed_at bigint NOT NULL CHECK (claimed_at >= 0),
    lease_expires_at bigint NOT NULL CHECK (lease_expires_at > claimed_at),
    UNIQUE (route_id, fencing_token)
);

CREATE UNIQUE INDEX IF NOT EXISTS work_claims_one_active_per_route_idx
    ON work_claims (route_id) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS work_claims_route_history_idx
    ON work_claims (route_id, fencing_token);

CREATE OR REPLACE FUNCTION protect_work_claim()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'work claims cannot be deleted';
    END IF;
    IF NEW.claim_id <> OLD.claim_id
       OR NEW.route_id <> OLD.route_id
       OR NEW.worker_service_id <> OLD.worker_service_id
       OR NEW.worker_instance_id <> OLD.worker_instance_id
       OR NEW.fencing_token <> OLD.fencing_token
       OR NEW.claimed_at <> OLD.claimed_at THEN
        RAISE EXCEPTION 'only status and lease_expires_at may change on a work claim';
    END IF;
    IF OLD.status <> 'active' THEN
        RAISE EXCEPTION 'work claim status % is terminal', OLD.status;
    END IF;
    IF NEW.status = 'active' THEN
        IF NEW.lease_expires_at <= OLD.lease_expires_at THEN
            RAISE EXCEPTION 'work claim renewal must extend the lease';
        END IF;
    ELSIF NEW.lease_expires_at <> OLD.lease_expires_at THEN
        RAISE EXCEPTION 'a terminal work claim transition must not change the lease';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS work_claims_protect ON work_claims;
CREATE TRIGGER work_claims_protect
BEFORE UPDATE OR DELETE ON work_claims
FOR EACH ROW EXECUTE FUNCTION protect_work_claim();

INSERT INTO kernel_schema_migrations (version, name)
VALUES (17, 'work_claims')
ON CONFLICT (version) DO NOTHING;
