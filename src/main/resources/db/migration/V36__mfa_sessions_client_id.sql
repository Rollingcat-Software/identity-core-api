-- V36: Bind OAuth2 client_id to mfa_sessions for cross-client replay prevention
--
-- The hosted-login flow creates an MfaSession when the user submits the
-- password at verify.fivucsas.com/login?client_id=X. After MFA completes,
-- /api/v1/oauth2/authorize/complete trades the session for an auth code.
--
-- Before this migration the code-mint endpoint accepted any completed
-- MfaSession belonging to the user's tenant — so a completed session for
-- client A could be replayed against client B (cross-client code replay
-- within the same tenant).
--
-- Fix: remember the client_id on the session, then enforce at completion
-- time that body.clientId matches session.client_id (or session.client_id
-- IS NULL for the legacy widget step-up MFA flow, which is client-agnostic
-- by design).
--
-- Column is nullable because:
--   1. Existing in-flight sessions at deploy time don't have a client_id.
--   2. Widget step-up MFA flow still needs to work without one.

ALTER TABLE mfa_sessions
    ADD COLUMN IF NOT EXISTS client_id VARCHAR(128);
