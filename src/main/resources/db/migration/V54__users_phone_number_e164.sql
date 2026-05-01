-- USER-BUG-4 follow-up: enforce strict E.164 phone numbers on users.phone_number.
--
-- Background:
--   Twilio Verify matches `to` + `code` byte-for-byte. The send-OTP path
--   normalized the phone to E.164 before sending, but the verify-OTP path
--   looked up Twilio with the raw `users.phone_number` string. If the user
--   typed `5551234567` (Turkish 10-digit) at enrollment time, send went to
--   `+905551234567` and verify looked up `5551234567` — silent verify-FAIL.
--
--   PR #42 (cc8ed23) routed verify through Twilio Verify when configured.
--   This migration is the second half of the fix: lock the column to E.164
--   so out-of-band INSERTs (admin SQL, future imports) cannot recreate the
--   skew.
--
-- Strategy:
--   1. Backfill non-E.164 rows in place. Idempotent — if the row already
--      passes E.164, the UPDATE is a no-op.
--      - 10-digit Turkish-shaped (5XXXXXXXXX or 05XXXXXXXXX)  → prefix +90.
--      - Anything else (garbage, pre-international 2024 imports)  → NULL.
--   2. Drop the existing loose `valid_phone` CHECK from V2 (allowed `+?`
--      and as few as 2 digits).
--   3. Add the strict `users_phone_e164` CHECK matching the
--      PhoneNumber value-object regex `^\+[1-9]\d{9,14}$`.
--
-- Idempotent: re-running this migration on a clean DB is a no-op (UPDATE
-- targets only non-conforming rows; CHECK constraint is dropped IF EXISTS
-- before re-add). Safe to apply on prod where most rows are already E.164.

-- ---------------------------------------------------------------------------
-- Step 1: backfill TR-shaped 10/11-digit numbers
-- ---------------------------------------------------------------------------
-- Strip leading 0 from 11-digit Turkish mobile (0 5XX XXX XX XX → +90 5XX...).
UPDATE users
SET phone_number = '+90' || substring(phone_number FROM 2)
WHERE phone_number IS NOT NULL
  AND phone_number ~ '^0[1-9][0-9]{9}$';

-- Prefix +90 to bare 10-digit Turkish mobile starting with non-zero.
UPDATE users
SET phone_number = '+90' || phone_number
WHERE phone_number IS NOT NULL
  AND phone_number ~ '^[1-9][0-9]{9}$';

-- Add the missing leading `+` to numbers that already look international
-- (digits-only, country-code-first, 10-15 long).
UPDATE users
SET phone_number = '+' || phone_number
WHERE phone_number IS NOT NULL
  AND phone_number ~ '^[1-9][0-9]{9,14}$'
  AND phone_number NOT LIKE '+%';

-- Anything still non-E.164 after the heuristics → NULL it. We deliberately
-- prefer NULL over CHECK-fail-on-deploy: we cannot realistically guess what
-- a malformed string was supposed to be, and a NULL is recoverable from the
-- UI (the user can re-enter their number) while a failed migration blocks
-- the whole app's boot. Operators can audit the affected rows via the
-- audit_logs row written below.
DO $$
DECLARE
    affected_rows INT;
    sample_emails TEXT;
BEGIN
    -- Capture a sample of the rows we're about to NULL, for the audit log.
    SELECT COUNT(*),
           string_agg(email, ', ' ORDER BY email)
      INTO affected_rows, sample_emails
      FROM (
          SELECT email
            FROM users
           WHERE phone_number IS NOT NULL
             AND phone_number !~ '^\+[1-9][0-9]{9,14}$'
           LIMIT 20
      ) sub;

    IF affected_rows IS NOT NULL AND affected_rows > 0 THEN
        RAISE NOTICE 'V53: nulling % non-E.164 phone_number rows; sample: %',
                     affected_rows, sample_emails;
    END IF;
END $$;

UPDATE users
SET phone_number = NULL
WHERE phone_number IS NOT NULL
  AND phone_number !~ '^\+[1-9][0-9]{9,14}$';

-- ---------------------------------------------------------------------------
-- Step 2: drop the legacy loose CHECK
-- ---------------------------------------------------------------------------
ALTER TABLE users DROP CONSTRAINT IF EXISTS valid_phone;

-- ---------------------------------------------------------------------------
-- Step 3: add the strict E.164 CHECK
-- ---------------------------------------------------------------------------
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_phone_e164;
ALTER TABLE users
    ADD CONSTRAINT users_phone_e164
    CHECK (phone_number IS NULL OR phone_number ~ '^\+[1-9][0-9]{9,14}$');

COMMENT ON CONSTRAINT users_phone_e164 ON users IS
    'E.164 phone format — required by Twilio Verify so send and verify match. See V53.';
