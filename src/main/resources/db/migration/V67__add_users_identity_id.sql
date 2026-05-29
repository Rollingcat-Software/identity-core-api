-- V67: Identity & Account-Linking — Phase 1
--
-- Adds `users.identity_id` (nullable FK to identities) and BACKFILLS one identity
-- per DISTINCT email (case-insensitive), linking ALL users that share that email
-- to the same identity.
--
-- WHY group by distinct email (not strictly 1:1 per user):
--   `users` has only a (tenant_id, email) UNIQUE (V2 unique_tenant_email) — NOT a
--   global unique. The same person can therefore hold accounts in several tenants
--   under the SAME email (e.g. the design doc's ahmet.abdullah operating both
--   Fivucsas and Marmara). identity_emails enforces a CASE-INSENSITIVE GLOBAL
--   UNIQUE on the email, so we MUST create exactly ONE identity per distinct
--   lower(email) and point every same-email membership at it. This both
--   (a) satisfies the identity_emails UNIQUE and (b) correctly pre-links
--   same-person/same-email accounts. For the common case (distinct emails) the
--   loop degenerates to 1:1.
--
-- RAW `users` (no soft-delete filter): the entity hides deleted_at IS NOT NULL
-- rows via @SQLRestriction, but this migration is raw SQL and intentionally sees
-- ALL rows incl. soft-deleted ones — they get identities too, so a later
-- SET NOT NULL (follow-up migration) is satisfiable for every row.
--
-- IDEMPOTENT: ADD COLUMN IF NOT EXISTS; the loop only touches users whose
-- identity_id IS NULL and only creates an identity/email when one does not yet
-- exist for that email. Re-running is a no-op.

-- ---------------------------------------------------------------------------
-- Step 1: add the nullable FK column. NOT NULL is deferred to a follow-up
--         migration once the prod backfill is confirmed 100% populated.
-- ---------------------------------------------------------------------------
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS identity_id UUID REFERENCES identities (id);

CREATE INDEX IF NOT EXISTS idx_users_identity_id ON users (identity_id);

-- ---------------------------------------------------------------------------
-- Step 2: backfill — one identity + one verified identity_emails row per
--         distinct lower(email); link every same-email user to it.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    rec            RECORD;
    v_identity_id  UUID;
    v_display_name TEXT;
    remaining      BIGINT;
BEGIN
    FOR rec IN
        SELECT lower(email) AS norm_email
          FROM users
         WHERE identity_id IS NULL
         GROUP BY lower(email)
    LOOP
        -- Reuse an existing identity for this email if one already exists
        -- (idempotent re-run / a sibling user already processed it).
        SELECT ie.identity_id
          INTO v_identity_id
          FROM identity_emails ie
         WHERE lower(ie.email) = rec.norm_email
         LIMIT 1;

        IF v_identity_id IS NULL THEN
            -- display_name = trimmed "first_name last_name" of ANY one user
            -- sharing this email (NULL if it trims to empty).
            SELECT NULLIF(btrim(concat_ws(' ', u.first_name, u.last_name)), '')
              INTO v_display_name
              FROM users u
             WHERE lower(u.email) = rec.norm_email
             ORDER BY u.created_at
             LIMIT 1;

            INSERT INTO identities (display_name, status, created_at, updated_at)
            VALUES (v_display_name, 'ACTIVE', now(), now())
            RETURNING id INTO v_identity_id;

            -- Existing users are trusted → the email is pre-verified. Preserve
            -- the original (non-lowercased) casing of one of the rows for display.
            INSERT INTO identity_emails (identity_id, email, verified, verified_at, created_at)
            SELECT v_identity_id, u.email, true, now(), now()
              FROM users u
             WHERE lower(u.email) = rec.norm_email
             ORDER BY u.created_at
             LIMIT 1;
        END IF;

        -- Link ALL users sharing this email (incl. soft-deleted) to the identity.
        UPDATE users
           SET identity_id = v_identity_id
         WHERE lower(email) = rec.norm_email
           AND identity_id IS NULL;
    END LOOP;

    -- ---------------------------------------------------------------------------
    -- Step 3: assert the backfill is complete. Fail LOUD on any residual NULL so
    --         a partial backfill aborts the deploy rather than shipping a
    --         half-populated table (the follow-up SET NOT NULL depends on this).
    -- ---------------------------------------------------------------------------
    SELECT COUNT(*) INTO remaining FROM users WHERE identity_id IS NULL;
    IF remaining > 0 THEN
        RAISE EXCEPTION
            'V67 backfill incomplete: % users still have NULL identity_id', remaining;
    END IF;

    RAISE NOTICE 'V67 backfill complete: every users row now has an identity_id.';
END $$;

COMMENT ON COLUMN users.identity_id IS
    'FK to the platform-level identity (person) that owns this tenant membership '
    '(Model A, Phase 1). Nullable for now; SET NOT NULL in a follow-up migration '
    'after prod backfill is confirmed. See docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md.';
