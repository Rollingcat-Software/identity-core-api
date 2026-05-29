-- V64: DNS-TXT domain-ownership verification + per-tenant default member role.
--
-- Two related self-service / onboarding features ship together here:
--
--   1. DNS-TXT domain verification.
--      V63 added tenant_email_domains.verified. A self-service tenant claims a
--      domain as verified=false; until ownership is proven it does NOT auto-bind
--      other registrants (RegisterUserService.resolveTenantByEmailDomain only
--      honours verified=true rows) nor satisfy enforce_domain_matching. This
--      migration adds the state needed to PROVE ownership via a DNS TXT record:
--        - verification_token        : the per-(tenant,domain) secret the admin
--                                      must publish in a TXT record. NULL once
--                                      the domain is verified (cleared on success)
--                                      or before a challenge has been requested.
--        - verification_requested_at : when the current token was (re)issued —
--                                      lets the UI show "requested N minutes ago"
--                                      and supports a future token-TTL policy.
--      The admin requests a challenge (POST .../{domain}/verification → token +
--      the exact TXT record), publishes `fivucsas-domain-verification={token}`
--      under `_fivucsas-verify.{domain}`, then calls POST .../{domain}/verify
--      which performs a DNS TXT lookup and flips verified=true on a match.
--
--   2. Per-tenant default member role (default-role-on-join / JIT-lite).
--      When a registrant auto-joins a tenant via a VERIFIED email domain, they
--      should land with a sensible baseline role. tenants.default_member_role
--      names the per-tenant role (by Role.name) assigned on auto-join. NULL =
--      fall back to the seeded baseline role (USER). Settable via the tenant
--      update API and surfaced in the tenant response.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS on every column; no backfill needed
-- (all three default to NULL, which preserves current behaviour).

-- ============================================================================
-- 1. tenant_email_domains — DNS-TXT verification challenge state
-- ============================================================================

ALTER TABLE tenant_email_domains
    ADD COLUMN IF NOT EXISTS verification_token VARCHAR(128);

ALTER TABLE tenant_email_domains
    ADD COLUMN IF NOT EXISTS verification_requested_at TIMESTAMPTZ;

COMMENT ON COLUMN tenant_email_domains.verification_token IS
    'Per-(tenant,domain) DNS-TXT verification secret. The admin publishes '
    '"fivucsas-domain-verification=<token>" as a TXT record under '
    '"_fivucsas-verify.<domain>". NULL before a challenge is requested and after '
    'the domain is verified (the token is cleared on success). See Flyway V63 '
    '(verified flag) and the TenantEmailDomainController verification endpoints.';

COMMENT ON COLUMN tenant_email_domains.verification_requested_at IS
    'Timestamp the current verification_token was (re)issued. Drives the admin '
    'UI "requested N ago" hint and any future token-TTL policy.';

-- ============================================================================
-- 2. tenants — default member role applied on verified-domain auto-join
-- ============================================================================

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS default_member_role VARCHAR(100);

COMMENT ON COLUMN tenants.default_member_role IS
    'Name (roles.name) of the per-tenant role auto-assigned to a user who joins '
    'this tenant by registering with a VERIFIED email domain (V63). NULL = fall '
    'back to the seeded baseline role ("USER"). Settable via PUT /api/v1/tenants/{id}.';
