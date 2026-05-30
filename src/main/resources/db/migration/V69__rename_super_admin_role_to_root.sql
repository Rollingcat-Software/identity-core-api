-- V69: Rename the global SUPER_ADMIN role -> ROOT + one-time user_type tier sync.
--
-- Motivation (see docs/IDENTITY_ROLE_UNIFICATION.md):
--   The platform top tier was named in two places that drifted: the `user_type`
--   enum (ROOT > TENANT_ADMIN > ...) — which EVERY backend gate keys off — and a
--   seeded RBAC role literally named "SUPER_ADMIN". There is no "ROOT" role, only
--   a "SUPER_ADMIN" role + a "ROOT" user_type (two names, one tier). `/auth/me`
--   returned the ROLE, so the frontend inferred the tier from the role string while
--   the backend gated on user_type; when they disagreed (e.g. `ahabgu`: role
--   SUPER_ADMIN, user_type TENANT_ADMIN) the UI showed super-admin but the backend
--   denied cross-tenant.
--
-- This migration:
--   1. Renames the global SUPER_ADMIN role (id 10000000-...001) -> ROOT so the role
--      name matches the user_type tier. UUID + permission grants are UNCHANGED, so
--      every existing user_roles assignment and role_permissions grant keeps working.
--   2. One-time, idempotent, ELEVATE-ONLY tier sync (mirrors V45 §4's intent):
--        - every user holding the ROOT role  -> user_type='ROOT'
--        - every user holding any TENANT_ADMIN role whose user_type ranks BELOW
--          TENANT_ADMIN -> user_type='TENANT_ADMIN'
--      Nobody is demoted (elevate-only) — demotion stays an explicit admin action.
--      This is what permanently fixes `ahabgu` (ROOT role -> user_type ROOT).
--
-- Idempotent + guarded: the rename only fires while the row is still named
-- SUPER_ADMIN (guard `AND name='SUPER_ADMIN'`), so re-applying after the rename is
-- a no-op. The tier sync re-reads the (renamed) ROOT role by id, so it is correct
-- whether it runs before or after the rename within this same transaction.

-- ============================================================================
-- 1. Rename the global SUPER_ADMIN role -> ROOT (idempotent guard)
-- ============================================================================

UPDATE roles
SET name = 'ROOT',
    updated_at = now()
WHERE id = '10000000-0000-0000-0000-000000000001'
  AND name = 'SUPER_ADMIN';

-- ============================================================================
-- 2a. Tier sync: ROOT-role holders -> user_type = 'ROOT' (elevate-only)
-- ============================================================================
--
-- Match by role id (stable across the rename). Only elevate users below ROOT —
-- ROOT outranks everyone, so the `<> 'ROOT'` guard makes this idempotent.

UPDATE users u
SET user_type = 'ROOT',
    updated_at = CURRENT_TIMESTAMP
WHERE u.user_type <> 'ROOT'
  AND EXISTS (
      SELECT 1
      FROM user_roles ur
      WHERE ur.user_id = u.id
        AND ur.role_id = '10000000-0000-0000-0000-000000000001'
  );

-- ============================================================================
-- 2b. Tier sync: TENANT_ADMIN-role holders below TENANT_ADMIN -> 'TENANT_ADMIN'
-- ============================================================================
--
-- Match by role NAME = 'TENANT_ADMIN' (covers the global template role
-- 20000000-...001 AND every per-tenant TENANT_ADMIN role). Elevate-only: only
-- users currently BELOW TENANT_ADMIN in the hierarchy (TENANT_MEMBER, GUEST) are
-- bumped; ROOT and existing TENANT_ADMIN users are untouched (no demotion).

UPDATE users u
SET user_type = 'TENANT_ADMIN',
    updated_at = CURRENT_TIMESTAMP
WHERE u.user_type IN ('TENANT_MEMBER', 'GUEST')
  AND EXISTS (
      SELECT 1
      FROM user_roles ur
      JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = u.id
        AND r.name = 'TENANT_ADMIN'
        AND r.is_active = TRUE
  );
