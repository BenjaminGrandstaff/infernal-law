-- Authority grants were strictly append-only: the trigger rejected every
-- UPDATE and DELETE, so a grant issued once could never be withdrawn. Its
-- only expiry was a `valid_until` chosen when it was created, which cannot
-- help when a grant was issued in error or a service's authority is being
-- reduced.
--
-- Append-only is worth keeping: history must not be rewritten. So rather
-- than relaxing the trigger, this adds a single monotonic transition --
-- `revoked_at` NULL -> a timestamp -- and continues to reject everything
-- else, including un-revoking. A revoked grant keeps its row, its reason,
-- and its administrator, and the revocation is itself audited.

ALTER TABLE authority_grants
    ADD COLUMN IF NOT EXISTS revoked_at bigint;

ALTER TABLE authority_grants
    DROP CONSTRAINT IF EXISTS authority_grants_revoked_at_check;
ALTER TABLE authority_grants
    ADD CONSTRAINT authority_grants_revoked_at_check
        CHECK (revoked_at IS NULL OR revoked_at >= 0);

ALTER TABLE authority_grant_administration_audit
    DROP CONSTRAINT IF EXISTS authority_grant_administration_audit_outcome_check;
ALTER TABLE authority_grant_administration_audit
    ADD CONSTRAINT authority_grant_administration_audit_outcome_check
        CHECK (outcome IN (
            'created',
            'create_conflict_rejected',
            'revoked',
            'revoke_no_op'
        ));

-- Permits exactly one mutation: setting `revoked_at` on a grant that has
-- not been revoked. Every other column must be unchanged, and DELETE stays
-- forbidden outright.
CREATE OR REPLACE FUNCTION reject_authority_grant_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'authority grants are append-only';
    END IF;

    IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
        RAISE EXCEPTION 'authority grants are append-only';
    END IF;

    IF NEW.grant_id IS DISTINCT FROM OLD.grant_id
       OR NEW.source_service_id IS DISTINCT FROM OLD.source_service_id
       OR NEW.action IS DISTINCT FROM OLD.action
       OR NEW.scope IS DISTINCT FROM OLD.scope
       OR NEW.artifact_schema_version_id IS DISTINCT FROM OLD.artifact_schema_version_id
       OR NEW.permission_policy_schema_version_id
            IS DISTINCT FROM OLD.permission_policy_schema_version_id
       OR NEW.destination_service_id IS DISTINCT FROM OLD.destination_service_id
       OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
       OR NEW.valid_until IS DISTINCT FROM OLD.valid_until
       OR NEW.administrator_identity IS DISTINCT FROM OLD.administrator_identity
       OR NEW.reason IS DISTINCT FROM OLD.reason
       OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'authority grants are append-only';
    END IF;

    RETURN NEW;
END;
$$;

-- Revoking an already-revoked grant is a no-op rather than an error, so a
-- reconciler can converge without needing to know the current state.
CREATE OR REPLACE FUNCTION revoke_authority_grant(
    requested_grant_id uuid,
    requested_administrator_identity text,
    requested_reason text,
    requested_correlation_id uuid,
    requested_revoked_at bigint
)
RETURNS TABLE (result_grant_id uuid, result_revoked_at bigint, result_outcome text)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    existing public.authority_grants%ROWTYPE;
BEGIN
    IF requested_administrator_identity IS NULL
       OR char_length(btrim(requested_administrator_identity)) NOT BETWEEN 1 AND 200
       OR requested_reason IS NULL
       OR char_length(btrim(requested_reason)) NOT BETWEEN 1 AND 1000
       OR requested_revoked_at < 0 THEN
        RAISE EXCEPTION 'invalid authority grant administration metadata';
    END IF;

    SELECT * INTO existing FROM public.authority_grants
    WHERE grant_id = requested_grant_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority grant % was not found', requested_grant_id;
    END IF;

    IF existing.revoked_at IS NOT NULL THEN
        INSERT INTO public.authority_grant_administration_audit
            (grant_id, outcome, administrator_identity, reason, correlation_id, recorded_at)
        VALUES (requested_grant_id, 'revoke_no_op',
                btrim(requested_administrator_identity), btrim(requested_reason),
                requested_correlation_id, requested_revoked_at);
        RETURN QUERY SELECT existing.grant_id, existing.revoked_at, 'no_op'::text;
        RETURN;
    END IF;

    UPDATE public.authority_grants
    SET revoked_at = requested_revoked_at
    WHERE grant_id = requested_grant_id;

    INSERT INTO public.authority_grant_administration_audit
        (grant_id, outcome, administrator_identity, reason, correlation_id, recorded_at)
    VALUES (requested_grant_id, 'revoked',
            btrim(requested_administrator_identity), btrim(requested_reason),
            requested_correlation_id, requested_revoked_at);

    RETURN QUERY SELECT requested_grant_id, requested_revoked_at, 'revoked'::text;
END;
$$;

INSERT INTO kernel_schema_migrations (version, name)
VALUES (19, 'revoke_authority_grants')
ON CONFLICT (version) DO NOTHING;
