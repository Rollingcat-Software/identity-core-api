-- V84: Bind refresh tokens to their issuing OAuth2 client (security — API-2).
--
-- Root cause: refresh_tokens had no client column, so a refresh token minted
-- for app A's client_id was replayable by app B's client and got reissued
-- scoped to B. This adds a NULLABLE client_id so the OAuth2 refresh-token grant
-- can reject a cross-client replay (existing.client_id != requesting client).
--
-- ADDITIVE + REVERSIBLE:
--   * The column is NULLABLE with NO backfill. NULL = legacy / client-unbound
--     (minted by the non-OAuth /auth/login, register, MFA-step, membership-switch,
--     and usernameless paths). Those keep refreshing unchanged (grace window).
--   * Only the OAuth2 authorization_code exchange stamps client_id from V84 on.
--   * The strict cross-client rejection is gated behind the runtime flag
--     app.oauth2.refresh-token.client-binding-enforced (default ENFORCE), so it
--     can be turned off via APP_OAUTH2_REFRESH_TOKEN_CLIENT_BINDING_ENFORCED=false
--     without a redeploy and without touching this schema.
--
-- No FK to oauth2_clients on purpose: client_id here is the OAuth2 wire client_id
-- string (oauth2_clients.client_id), and we never want a client deletion to
-- cascade-delete or block live refresh-token rows. The match is a value compare.

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS client_id VARCHAR(128);

COMMENT ON COLUMN refresh_tokens.client_id IS
    'OAuth2 client_id (oauth2_clients.client_id) this refresh token was issued to. '
    'NULL = legacy / client-unbound (minted outside the OAuth2 code-exchange path). '
    'On the refresh_token grant a non-NULL value must equal the requesting client '
    'when app.oauth2.refresh-token.client-binding-enforced is true (API-2).';

-- Index the binding so a future per-client revoke / audit query stays cheap.
-- Partial (non-NULL only) keeps it small since legacy rows are unbound.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id
    ON refresh_tokens (client_id)
    WHERE client_id IS NOT NULL;
