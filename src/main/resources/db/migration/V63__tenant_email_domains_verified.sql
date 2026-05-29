-- V63: tenant_email_domains.verified — domain-ownership gate for self-service onboarding
--
-- Motivation:
--   Self-service tenant onboarding (POST /api/v1/onboarding/register) lets a new
--   organisation CLAIM an email domain at sign-up. But a claim is not proof of
--   ownership — a Round-2 feature (DNS-TXT verification) or a SUPER_ADMIN must
--   confirm it. Until then, the claimed domain must NOT auto-bind OTHER
--   registrants to the new tenant and must NOT satisfy enforce_domain_matching.
--
-- Strategy:
--   Add a `verified` flag. Self-service claims insert verified=false. Every
--   PRE-EXISTING domain (Marmara etc., seeded via V44 backfill) is set
--   verified=true so today's auto-binding behaviour is unchanged. The
--   RegisterUserService domain-resolution path only honours verified=true rows.
--
-- Idempotent: IF NOT EXISTS on the column; the backfill UPDATE is naturally
-- replay-safe.

-- ============================================================================
-- 1. Column
-- ============================================================================

ALTER TABLE tenant_email_domains
    ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN tenant_email_domains.verified IS
    'TRUE once domain ownership is established (DNS-TXT verification or SUPER_ADMIN approval). '
    'Only verified domains auto-bind new registrants and satisfy enforce_domain_matching. '
    'Self-service onboarding claims a domain as verified=false.';

-- ============================================================================
-- 2. Backfill — every domain that existed BEFORE self-service onboarding is
--    trusted, so current auto-binding behaviour is preserved.
-- ============================================================================
--
-- This migration runs once, before any self-service tenant can exist, so every
-- row present at apply-time is an admin/seed-provisioned (trusted) domain.

UPDATE tenant_email_domains
SET verified = true
WHERE verified = false;
