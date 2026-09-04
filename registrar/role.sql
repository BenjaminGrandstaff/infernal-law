-- The registrar's own PostgreSQL role (ADR-0015).
--
-- It deliberately cannot read or write kernel state. Note how little it
-- needs: `set_service_communication_admission`, `create_authority_grant`
-- and `revoke_authority_grant` are SECURITY DEFINER, so the registrar
-- executes them without holding any privilege on the tables they write --
-- admission, grants, and their audit trails stay unreachable to it except
-- through those audited procedures.
--
-- Run once as a superuser against the kernel database, substituting a real
-- password:
--
--   psql "$KERNEL_DATABASE_URL" -v password="'...'" -f registrar/role.sql

CREATE ROLE infernal_registrar LOGIN PASSWORD :password;

GRANT CONNECT ON DATABASE infernal_law TO infernal_registrar;
GRANT USAGE ON SCHEMA public TO infernal_registrar;

-- Identities and enrollment bindings are plain tables the registrar owns
-- the lifecycle of.
GRANT SELECT, INSERT, UPDATE ON identities TO infernal_registrar;
GRANT SELECT, INSERT, UPDATE ON service_enrollment_bindings TO infernal_registrar;

-- Read-only, and only enough to make reconciliation idempotent: the
-- registrar must see which grants already exist before deciding whether to
-- create or revoke one. It has no write privilege here -- the append-only
-- trigger and the procedures are what mutate this table.
GRANT SELECT ON authority_grants TO infernal_registrar;
GRANT SELECT ON authority_schema_versions TO infernal_registrar;

GRANT EXECUTE ON FUNCTION set_service_communication_admission(
    uuid, boolean, text, text, uuid, bigint) TO infernal_registrar;
GRANT EXECUTE ON FUNCTION create_authority_grant(
    uuid, uuid, text, text, uuid, uuid, uuid, bigint, bigint, text, text, uuid, bigint)
    TO infernal_registrar;
GRANT EXECUTE ON FUNCTION revoke_authority_grant(
    uuid, text, text, uuid, bigint) TO infernal_registrar;

-- Explicitly withheld, listed so the intent is legible to a reviewer:
-- service_instances, service_instance_keys, service_enrollment_challenges,
-- authority_decisions, accepted_requests, request_routes, work_claims,
-- subscriptions, and every audit table. The registrar administers who may
-- exist and what they may do; it never touches what they have done.
