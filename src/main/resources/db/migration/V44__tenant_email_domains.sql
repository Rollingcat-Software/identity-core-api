-- V44: Tenant Email Domains (multi-domain tenant support)
--
-- Motivation:
--   A tenant can own MORE THAN ONE email domain. Marmara University is the
--   canonical example: staff use "marun.edu.tr" while students/faculty use
--   "marmara.edu.tr". Both should auto-resolve to the same tenant on
--   registration. The existing tenants.domain column only supports one
--   domain per tenant, which is not enough.
--
-- Strategy:
--   Introduce tenant_email_domains (tenant_id, email_domain) with a UNIQUE
--   constraint on email_domain so no domain can ever map to two tenants
--   (which would make auto-assignment ambiguous). One row per tenant is
--   flagged is_primary=true and backfilled from tenants.domain; additional
--   rows are added via the admin API.
--
-- This migration is IDEMPOTENT — every DDL uses IF NOT EXISTS and every
-- INSERT uses ON CONFLICT DO NOTHING so replays are safe.
--
-- The legacy tenants.domain column is NOT dropped here. That is a separate
-- follow-up PR after consumers migrate to tenant_email_domains.

-- ============================================================================
-- 1. Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_email_domains
(
    tenant_id    UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email_domain VARCHAR(253) NOT NULL,
    is_primary   BOOLEAN      NOT NULL DEFAULT false,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_tenant_email_domains PRIMARY KEY (tenant_id, email_domain),
    CONSTRAINT chk_tenant_email_domains_lowercase CHECK (email_domain = lower(email_domain)),
    CONSTRAINT chk_tenant_email_domains_no_at CHECK (position('@' in email_domain) = 0)
);

-- ============================================================================
-- 2. Constraints & Indexes
-- ============================================================================

-- A domain belongs to at most ONE tenant — no ambiguity on auto-assignment.
CREATE UNIQUE INDEX IF NOT EXISTS ux_tenant_email_domains_domain
    ON tenant_email_domains (email_domain);

-- Reverse lookup: "list every domain for this tenant" (admin panel).
CREATE INDEX IF NOT EXISTS idx_tenant_email_domains_tenant
    ON tenant_email_domains (tenant_id);

-- At most one primary domain per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS ux_tenant_email_domains_one_primary
    ON tenant_email_domains (tenant_id)
    WHERE is_primary = true;

COMMENT ON TABLE tenant_email_domains IS
    'Email-domain registry for tenant auto-assignment on signup. A tenant can own multiple domains; a domain may belong to at most one tenant.';
COMMENT ON COLUMN tenant_email_domains.email_domain IS
    'Lowercase FQDN (no @). RFC 1035 max length 253. Unique across all tenants.';
COMMENT ON COLUMN tenant_email_domains.is_primary IS
    'Marks the canonical display domain for the tenant. Exactly one per tenant (enforced by partial unique index).';

-- ============================================================================
-- 3. Backfill from tenants.domain
-- ============================================================================

-- Copy each existing tenants.domain into tenant_email_domains as primary.
-- Lowercased + trimmed for safety. NULL / empty domains are skipped.
INSERT INTO tenant_email_domains (tenant_id, email_domain, is_primary)
SELECT id,
       lower(trim(domain)),
       true
FROM tenants
WHERE domain IS NOT NULL
  AND length(trim(domain)) > 0
ON CONFLICT (tenant_id, email_domain) DO NOTHING;

-- ============================================================================
-- 4. Additional seed — Marmara University's secondary "marun.edu.tr" domain
-- ============================================================================
--
-- Guarded by EXISTS so it is safe to re-run and safe on fresh DBs where the
-- Marmara seed tenant has not yet been inserted (e.g. tests with a subset
-- of migrations applied out of order).

INSERT INTO tenant_email_domains (tenant_id, email_domain, is_primary)
SELECT '11111111-1111-1111-1111-111111111111'::uuid,
       'marun.edu.tr',
       false
WHERE EXISTS (
    SELECT 1 FROM tenants WHERE id = '11111111-1111-1111-1111-111111111111'::uuid
)
ON CONFLICT (tenant_id, email_domain) DO NOTHING;
