-- V80: Seed the native mobile (Android) OAuth 2.0 public client for hosted-first login.
--
-- Per the 2026-04-16 hosted-first pivot (docs/plans/CLIENT_APPS_PARITY.md) and the
-- 2026-06-02 mobile-auth architecture lock: the Android app authenticates by opening
-- verify.fivucsas.com/login in a Chrome Custom Tab (OAuth 2.0 + PKCE S256, RFC 8252)
-- and receives the authorization code on the `fivucsas://callback` custom scheme.
--
-- This client is PUBLIC (confidential = FALSE): a native app cannot keep a secret, so
-- PKCE S256 is the only client authentication (already enforced for public clients in
-- OAuth2Controller). The client_secret column is NOT NULL, so a clearly non-functional
-- placeholder is stored; it is never verified for public clients.
--
-- Idempotent: guarded by NOT EXISTS so it is safe to run manually on prod AND via Flyway.

INSERT INTO oauth2_clients (
    client_id,
    client_secret,
    client_name,
    redirect_uris,
    allowed_scopes,
    tenant_id,
    active,
    confidential
)
SELECT
    'fivucsas-mobile',
    'public-pkce-no-secret',                       -- unused for public clients (confidential=false)
    'FIVUCSAS Mobile (Android)',
    '["fivucsas://callback"]',                     -- RFC 8252 private-use URI scheme, exact-match
    'openid profile email',
    t.id,
    TRUE,
    FALSE                                          -- public client: PKCE S256 mandatory
FROM tenants t
WHERE t.slug = 'system'
  AND NOT EXISTS (
        SELECT 1 FROM oauth2_clients c WHERE c.client_id = 'fivucsas-mobile'
  )
LIMIT 1;
