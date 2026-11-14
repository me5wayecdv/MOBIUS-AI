-- Backstop for FR-AUTH-2: no investigation may do work without a live authorisation.
--
-- The service layer checks this too and returns a clean 409. The trigger exists because the
-- service is not the only writer: a migration, a repair script, or a future worker could
-- UPDATE investigations directly. Duplication here is deliberate - the trigger is the part
-- that cannot be bypassed from application code.
--
-- Carried over verbatim in behaviour from docs/DATABASE_SCHEMA.md 3.2. The doc is the
-- specification; this file is the executable copy, and tests/test_postgres_trigger.py
-- asserts each RAISE branch fires.

CREATE OR REPLACE FUNCTION enforce_authorization_scope() RETURNS trigger AS $$
DECLARE
    auth_max     smallint;
    auth_expires timestamptz;
    auth_revoked timestamptz;
BEGIN
    -- Pre-authorisation states exist so a refused scan is still auditable (AC-FR-AUTH-2).
    IF NEW.state IN ('INTAKE','SCOPE_BLOCKED') THEN
        RETURN NEW;
    END IF;

    IF NEW.authorization_id IS NULL THEN
        RAISE EXCEPTION 'investigation may not leave INTAKE without an authorization'
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT max_intensity, expires_at, revoked_at
      INTO auth_max, auth_expires, auth_revoked
      FROM authorizations WHERE id = NEW.authorization_id;

    IF auth_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'authorization % is revoked', NEW.authorization_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF auth_expires <= now() THEN
        RAISE EXCEPTION 'authorization % has expired', NEW.authorization_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.intensity > auth_max THEN
        RAISE EXCEPTION 'intensity % exceeds granted %, approval required',
            NEW.intensity, auth_max USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS investigations_scope_guard ON investigations;

CREATE TRIGGER investigations_scope_guard
    BEFORE INSERT OR UPDATE OF intensity, authorization_id, state ON investigations
    FOR EACH ROW EXECUTE FUNCTION enforce_authorization_scope();
