-- V42__totp_secret_check_encrypted.sql
--
-- AUDIT_2026-04-20 follow-up to V39 / TotpSecretMigrator:
-- enforce the encrypted-at-rest invariant for users.two_factor_secret via a
-- CHECK constraint. Once applied, any future INSERT/UPDATE that writes a
-- plaintext (non-prefixed) secret will fail at the database layer, closing
-- the gap identified in the Phase-1 security review (TOTP plaintext fallback).
--
-- Operator runbook:
--   1. Ensure FIVUCSAS_TOTP_ENC_KEY is set in prod (V39 requirement).
--   2. Flip FIVUCSAS_TOTP_MIGRATE_ON_BOOT=true, restart identity-core-api,
--      wait for "[TotpSecretMigrator] done" log line, flip flag back to false.
--   3. Apply this migration. If the ALTER TABLE fails with
--      "check constraint violated", it means at least one legacy plaintext row
--      is still present — re-run the migrator and retry.
--   4. Flip FIVUCSAS_TOTP_REJECT_PLAINTEXT=true so application-side reads
--      refuse plaintext as well (defense-in-depth).
--
-- Safety: adds only a constraint. Non-destructive, reversible via DROP
-- CONSTRAINT. No data is modified.

ALTER TABLE users
    ADD CONSTRAINT chk_two_factor_secret_encrypted
        CHECK (
            two_factor_secret IS NULL
            OR two_factor_secret LIKE 'enc:v1:%'
        );

COMMENT ON CONSTRAINT chk_two_factor_secret_encrypted ON users IS
    'BE-H3 Phase-1: two_factor_secret must be NULL or AES-GCM ciphertext (enc:v1:*). See V39 + V42 runbooks.';
