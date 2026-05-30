-- V70: guarantee every user has an identity, then enforce users.identity_id NOT NULL.
--
-- Identity Phase 1 (V65-V67) added the identity layer and backfilled existing users, but
-- the user-CREATION paths map the DOMAIN User to the entity without setting identity_id,
-- so NEW users would be inserted with a NULL FK. A BEFORE-INSERT trigger auto-assigns an
-- identity (reusing the existing one when the email already belongs to a person — "same
-- email = same person"), covering ALL app paths + direct SQL + any future caller. This
-- mirrors the V53 hard-delete trigger pattern. With the trigger in place, NOT NULL is safe.

CREATE OR REPLACE FUNCTION ensure_user_identity() RETURNS trigger AS $$
DECLARE
    v_identity uuid;
BEGIN
    IF NEW.identity_id IS NULL THEN
        -- Reuse an existing identity if this email is already known (links same-person rows).
        SELECT identity_id INTO v_identity
        FROM identity_emails
        WHERE lower(email) = lower(NEW.email)
        LIMIT 1;

        IF v_identity IS NULL THEN
            INSERT INTO identities (id, display_name, status, created_at, updated_at)
            VALUES (gen_random_uuid(),
                    NULLIF(btrim(concat_ws(' ', NEW.first_name, NEW.last_name)), ''),
                    'ACTIVE', now(), now())
            RETURNING id INTO v_identity;

            INSERT INTO identity_emails (id, identity_id, email, verified, verified_at, created_at)
            VALUES (gen_random_uuid(), v_identity, NEW.email,
                    COALESCE(NEW.email_verified, false),
                    CASE WHEN NEW.email_verified THEN now() ELSE NULL END,
                    now());
        END IF;

        NEW.identity_id := v_identity;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tg_users_ensure_identity ON users;
CREATE TRIGGER tg_users_ensure_identity
    BEFORE INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION ensure_user_identity();

-- Defensive backfill for any row that slipped through between Phase 1 and now (should be 0).
DO $$
DECLARE
    r RECORD;
    v_identity uuid;
BEGIN
    FOR r IN SELECT id, email, first_name, last_name, email_verified
             FROM users WHERE identity_id IS NULL LOOP
        SELECT identity_id INTO v_identity FROM identity_emails WHERE lower(email) = lower(r.email) LIMIT 1;
        IF v_identity IS NULL THEN
            INSERT INTO identities (id, display_name, status, created_at, updated_at)
            VALUES (gen_random_uuid(), NULLIF(btrim(concat_ws(' ', r.first_name, r.last_name)), ''),
                    'ACTIVE', now(), now())
            RETURNING id INTO v_identity;
            INSERT INTO identity_emails (id, identity_id, email, verified, verified_at, created_at)
            VALUES (gen_random_uuid(), v_identity, r.email, COALESCE(r.email_verified, false),
                    CASE WHEN r.email_verified THEN now() ELSE NULL END, now());
        END IF;
        UPDATE users SET identity_id = v_identity WHERE id = r.id;
    END LOOP;
END $$;

-- Self-gating: fail loud if anything is still NULL, then enforce the constraint.
DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM users WHERE identity_id IS NULL;
    IF n > 0 THEN
        RAISE EXCEPTION 'V70 precondition failed: % users still have NULL identity_id', n;
    END IF;
END $$;

ALTER TABLE users ALTER COLUMN identity_id SET NOT NULL;
