-- V66: Identity & Account-Linking — Phase 1
--
-- The verified email addresses a person controls. One identity may hold several
-- emails (the account-linking goal in Phase 2). The UNIQUE on the email is
-- CASE-INSENSITIVE so the same address can never anchor two identities.
--
-- Email type: `users.email` is VARCHAR(255) (V2) with NO citext extension in
-- this database — so we match that: VARCHAR(255) + a UNIQUE INDEX on lower(email)
-- to enforce case-insensitive uniqueness (the same idiom `idx_users_email` and
-- friends use lower()-free, but here uniqueness MUST be case-insensitive).
--
-- DESIGN NOTE — NOT TENANT-SCOPED: like `identities`, this is platform-level and
-- carries NO tenant_id / NO tenantFilter. See V65 + the design doc.

CREATE TABLE IF NOT EXISTS identity_emails
(
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID         NOT NULL REFERENCES identities (id),
    email       VARCHAR(255) NOT NULL,
    verified    BOOLEAN      NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Case-insensitive global uniqueness: one identity per distinct email address.
CREATE UNIQUE INDEX IF NOT EXISTS uq_identity_emails_lower_email
    ON identity_emails (lower(email));

-- Lookup all emails for an identity (the "person view").
CREATE INDEX IF NOT EXISTS idx_identity_emails_identity_id
    ON identity_emails (identity_id);

COMMENT ON TABLE identity_emails IS
    'Emails a person (identity) controls. Case-insensitive UNIQUE on lower(email). '
    'Cross-tenant by design — NOT tenant-scoped. See docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md.';
