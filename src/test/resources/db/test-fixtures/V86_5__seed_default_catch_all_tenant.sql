-- ============================================================================
-- TEST-ONLY MIGRATION (loaded only by the Testcontainers integration profile via
-- spring.flyway.locations=classpath:db/migration,classpath:db/test-fixtures).
-- This file is NOT on the production classpath; it never runs in prod.
-- ============================================================================
--
-- WHY THIS EXISTS
-- ---------------
-- The integration suite self-registers `@fivucsas.com` accounts with NO tenant
-- context and NO seeded email-domain row (UserApiIntegrationTest,
-- AuthenticationFlowIntegrationTest). RegisterUserService resolves a registrant's
-- tenant by: (1) TenantContext, (2) verified email-domain match, (3) legacy
-- tenants.domain, then (4) the `app.default-tenant-slug` catch-all tenant. On a
-- fresh Testcontainers DB none of (1)-(3) match and the catch-all tenant did not
-- exist, so every self-registration was rejected with HTTP 422
-- EmailDomainNotAllowed. This seeds that catch-all so registration lands
-- gracefully — exactly the PRODUCTION default-tenant mechanism. No production
-- validation is changed (prod has its own real default/onboarding tenants).
--
-- WHY A DEDICATED `default` TENANT (not the V1 `system` tenant)
-- ------------------------------------------------------------
-- The `system` tenant (V1) is given a 2-step "Default Login" flow
-- (PASSWORD + EMAIL_OTP) by V29, so a login there returns an MFA challenge
-- instead of tokens — which breaks the auth-flow ITs that expect a single
-- register→login→tokens round-trip. This tenant is created with NO custom auth
-- flow, so AuthenticateUserService falls back to single-step PASSWORD and mints
-- tokens directly. enforce_domain_matching is left at its default (false), so the
-- V62 email-domain gate is skipped; max_users is generous so the quota gate
-- (countByTenantId >= max_users) never trips across the suite's registrations.
--
-- The integration profile sets app.default-tenant-slug=default to point the
-- catch-all here.
--
-- Idempotent — ON CONFLICT (slug) DO NOTHING so replays / multiple class contexts
-- are safe. Uses a fixed UUID for determinism.
-- ============================================================================

INSERT INTO tenants (
    id, name, slug, contact_email, status, max_users, biometric_enabled,
    session_timeout_minutes, refresh_token_validity_days, is_active,
    enforce_domain_matching, created_at, updated_at
) VALUES (
    'dddddddd-0000-0000-0000-000000000001',
    'Integration Default Catch-All',
    'default',
    'default-catch-all@integration.test',
    'ACTIVE',
    1000000,
    true,
    30,
    7,
    true,
    false,
    NOW(),
    NOW()
) ON CONFLICT (slug) DO NOTHING;
