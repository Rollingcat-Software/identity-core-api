# Identity Role Unification — eliminate "SUPER_ADMIN", unify the top tier on "ROOT"

Status: **APPROVED 2026-05-30** (operator). UI label for the top tier = **"Root"**.

## Problem
Two parallel mechanisms name/gate the top admin tier, and they disagree:
- **`user_type`** enum (ROOT › TENANT_ADMIN › TENANT_MEMBER › GUEST) — the **capability
  tier**; every backend gate (`isRoot`, `isTenantAdmin`, `canAccessTenant`) keys off this.
- **RBAC `roles`** (SUPER_ADMIN, TENANT_ADMIN, USER…) — **permission grants**.

There is NO `ROOT` role — only a `SUPER_ADMIN` role + a `ROOT` user_type (two names, one
tier). `/auth/me` returns the **role**, never the **user_type**, so the frontend guesses the
tier from the role name while the backend gates on user_type. When they diverge (e.g.
`ahabgu`: role=SUPER_ADMIN, user_type=TENANT_ADMIN) the UI shows super-admin but the backend
denies cross-tenant. The same gap breaks any role↔user_type mismatch (a TENANT_ADMIN-by-role
who is TENANT_MEMBER-by-type → UI shows admin, backend 403s).

## Conceptual model (the intended two layers)
Having BOTH `user_type` and `role` is correct — they are two DIFFERENT layers:
- **`user_type` = platform-level (FIVUCSAS) tier.** Who are you to FIVUCSAS itself —
  operator (ROOT) / tenant administrator (TENANT_ADMIN) / tenant member (TENANT_MEMBER) /
  guest (GUEST). Cross-cutting, FIVUCSAS-owned; decides cross-tenant access + can-manage-tenant.
- **`role` + permissions = within-tenant RBAC.** What may you do INSIDE a specific tenant
  (e.g. Marmara) — granular, tenant-scoped, tenant-customizable (Auditor / Enrollment Manager /
  Viewer …).

**The design gap:** today the platform TIER is duplicated — it lives in `user_type`
(ROOT/TENANT_ADMIN) AND is re-encoded as seeded "tier roles" (`SUPER_ADMIN`, `TENANT_ADMIN`
roles). Two copies of the same tier in two systems that drift; the frontend reads the role,
the backend gates on user_type, and when they disagree you get the bug. The roles table is
doing two jobs (granular permissions = legit; re-encoding the tier = the gap). The fix makes
`user_type` the SOLE owner of the tier and lets `role` be purely about within-tenant
permissions.

## Decision
1. **`user_type` is the single authority for the platform tier** (it already is, in every
   backend gate). Roles are within-tenant permission grants — they must NOT be a second
   source of truth for the tier.
2. **Rename the global `SUPER_ADMIN` role → `ROOT`** so the role name matches the user_type
   tier. The word "SUPER_ADMIN" is removed across DB, backend, frontend.
3. **Expose `userType`** in `/auth/me` (UserResponse) so the frontend knows the real tier
   instead of inferring it from a role string.
4. **Frontend trusts `user_type`**: `isRoot` = `userType==='ROOT'` (matches the backend);
   UI labels the top tier **"Root"**.
5. **Keep role ↔ user_type in sync** so they can never drift again: a one-time backfill
   (migration) + ongoing elevate-on-grant in the role-assignment service.

## Backend (identity-core-api)
- **V69 migration** (`V69__rename_super_admin_role_to_root.sql`):
  - `UPDATE roles SET name='ROOT' WHERE id='10000000-0000-0000-0000-000000000001' AND name='SUPER_ADMIN';` (UUID + grants unchanged).
  - One-time sync (mirrors V45's intent): every user holding the ROOT role →
    `user_type='ROOT'`; every user holding a TENANT_ADMIN role but `user_type` below
    TENANT_ADMIN → `user_type='TENANT_ADMIN'`. (Fixes `ahabgu`.) Idempotent.
- **String literals** `"SUPER_ADMIN"` → `"ROOT"` everywhere (e.g. `entity/User.java` /
  `domain/model/user/User.java` `hasAnyRole(...)`, `security/AuthorizationService` `hasRole`,
  any `@PreAuthorize("hasRole('SUPER_ADMIN')")` / `hasAuthority('ROLE_SUPER_ADMIN')`). Method
  names: collapse `isSuperAdmin()` into `isRoot()` (keep one; update call sites incl.
  `TenantScopeResolver.isCrossTenantAdmin`).
- **`UserResponse` (+/auth/me)**: add `userType` (the enum name string). Do NOT remove
  `role`/`roles` (still used).
- **Ongoing sync** in `ManageUserRoleService` (the role grant/revoke choke point): when a
  user is granted the ROOT role, ELEVATE `user_type` to ROOT; when granted TENANT_ADMIN,
  elevate to at least TENANT_ADMIN. Elevate-only in v1 (never auto-demote on revoke — demotion
  stays an explicit admin action; avoids accidental privilege loss). Covers future drift.
- Keep `user_type` as the gate authority; this refactor renames + aligns, it does NOT rewire
  the gates (low authz risk).

## Frontend (web-app)
- `domain/models/User.ts`: rename the top `UserRole` member to **`ROOT = 'ROOT'`** (drop the
  `SUPER_ADMIN` value). Add `userType` to the model from `/auth/me`. `isRoot()` (rename
  `isSuperAdmin`) = `this.userType === 'ROOT'` (authoritative; fall back to role only if
  userType absent). `fromJSON` role map keeps `'ROOT'→ROOT` and `'SUPER_ADMIN'→ROOT`
  (back-compat through the transition).
- `isAdmin()` stays role/type tolerant (ROOT or TENANT_ADMIN).
- `ActiveTenantProvider`: `canSwitch = user?.isRoot()` (now userType-driven → matches backend
  `isCrossTenantAdmin`, so the switcher only shows when the backend will actually honor it).
- UI labels + i18n: render the top tier as **"Root"** (was "SUPER ADMIN"); update
  `PLATFORM_OWNER_ROLES`/`ADMIN_ROLES`/role-label maps + en.json/tr.json.

## Validation (staging → prod)
- Migration applies cleanly from current prod schema (head V68) on `identity_core_staging`.
- A user with the ROOT role → `user_type=ROOT`; cross-tenant `/tenants` returns all; switcher
  populates. A TENANT_ADMIN-by-role with lower user_type → elevated to TENANT_ADMIN; admin
  endpoints stop 403'ing.
- Browser re-test (e2e-sweep): role badge shows "Root"; tenant list + switcher work; no 403s.
- `ahabgu` ends up `user_type=ROOT` via the backfill (proper fix, no manual poke).

## Reversibility
Role rename is a single UPDATE (reversible). user_type elevations are data (a follow-up could
recompute). Frontend label/enum changes are code-reversible.
