-- V72: discoverable (resident-key) passkey support for usernameless login.
--
-- Phase 1 of the passkey hybrid-login plan adds two columns to
-- webauthn_credentials:
--   * discoverable  — whether the credential was created with
--                     residentKey="required" (a resident key the
--                     authenticator can surface without an allowCredentials
--                     hint), enabling usernameless assertion.
--   * user_handle   — the WebAuthn user handle (PublicKeyCredentialUserEntity.id)
--                     stored base64url-encoded. On a usernameless assertion the
--                     authenticator echoes this value; the RP resolves the
--                     owning user from it instead of from an up-front email.
--
-- Existing credentials predate discoverable passkeys: they default to
-- discoverable=false and a NULL user_handle (they remain usable through the
-- email-scoped allowCredentials assertion path, which is unchanged).

ALTER TABLE webauthn_credentials
    ADD COLUMN IF NOT EXISTS discoverable boolean NOT NULL DEFAULT false;

ALTER TABLE webauthn_credentials
    ADD COLUMN IF NOT EXISTS user_handle varchar(255);

-- Usernameless assertion resolves a credential set from the user_handle, so
-- index it. Partial index keeps it small — only discoverable rows ever carry a
-- non-NULL handle in normal operation.
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_handle
    ON webauthn_credentials (user_handle)
    WHERE user_handle IS NOT NULL;
