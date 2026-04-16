-- V34: Add confidential flag to oauth2_clients
--
-- Per RFC 6749 §2.1, OAuth 2.0 clients are either:
--   confidential — capable of securely holding a client_secret (server-side web app)
--   public       — cannot hold secrets (SPA, native app, CLI)
--
-- Public clients MUST use PKCE S256 (RFC 7636). Plain is rejected.
-- The OAuth2Controller reads this flag at /authorize/complete to enforce PKCE
-- requirements before minting an authorization code.
--
-- Default TRUE so existing seeded rows (e.g. fivucsas-web-dashboard) keep their
-- existing behavior. New public SPA/native registrations should set FALSE.

ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS confidential BOOLEAN NOT NULL DEFAULT TRUE;
