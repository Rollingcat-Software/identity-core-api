-- Refresh-token secret hashing at rest (P1-1, SECURITY_REVIEW_2026-05-01.md).
--
-- Wire format moves to <token_id>.<secret>. Only sha256(secret) is stored.
-- The plaintext `token` column is intentionally kept in this migration to
-- preserve dual-read backwards compatibility for tokens issued before this
-- PR; a follow-up migration will drop it after operator soak.

ALTER TABLE refresh_tokens
    ADD COLUMN token_secret_hash BYTEA;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_secret_hash
    ON refresh_tokens (token_secret_hash);

-- Backfill is intentionally not in the migration. Tokens are short-lived
-- (jwt.refresh-expiration default = 7 days), so existing rows naturally
-- roll off via TTL. Operator decision: rotate now (revoke all sessions)
-- or wait the TTL window.

COMMENT ON COLUMN refresh_tokens.token_secret_hash IS
    'SHA-256 of the refresh-token secret-half. Token wire format is <id>.<secret>; the secret is never stored plaintext. Plaintext token column kept for backwards-compat read; will be dropped in a follow-up migration.';
