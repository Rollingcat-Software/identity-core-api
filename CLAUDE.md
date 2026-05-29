# CLAUDE.md - Identity Core API

## Project Overview

Java 21 / Spring Boot 3.4.7 backend API for FIVUCSAS biometric identity platform.
Hexagonal Architecture with Ports and Adapters. Production URL: https://api.fivucsas.com

## Build & Deploy

```bash
# Production (Docker — Maven is NOT installed on VPS)
cd /opt/projects/fivucsas/identity-core-api
docker compose -f docker-compose.prod.yml --env-file .env.prod build --no-cache identity-core-api
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d identity-core-api
```

**Always use `--env-file .env.prod`** on VPS. Runs on port 8080. Swagger at `/swagger-ui.html`.

## Key Directories

- `controller/` - 25 REST controllers (incl. OAuth2, OpenIDConfig, NFC, WebAuthn)
- `application/service/handler/` - 10 auth method handlers (all WORKING)
- `application/port/output/` - Output ports (hexagonal)
- `infrastructure/` - Adapters (BiometricService, WebAuthn)
- `entity/` - JPA entities
- `repository/` - Spring Data repositories

## Auth Methods (ALL 10 WORKING)

Password, EmailOtp, SmsOtp, Totp, QrCode, Face, Fingerprint, Voice, NfcDocument, HardwareKey

**Note (P1.4)**: `FINGERPRINT` is delivered exclusively via WebAuthn platform authenticator
(FingerprintAuthHandler). The legacy server-side fingerprint biometric path
(`/api/v1/biometric/fingerprint/{enroll,verify,delete}` + BiometricServicePort.{enroll,verify,delete}Fingerprint)
was removed because the biometric-processor backend was a SHA-256 hash placeholder,
not a real biometric. The `AuthMethodType.FINGERPRINT` enum value is retained
(used by WebAuthn) and 3 existing user_enrollments rows continue to work.

## Key Patterns

- **N-step MFA**: JWT deferred until all steps complete. `POST /auth/mfa/step` with session token. RFC 8176 `amr` claim.
- **WebAuthn base64**: `decodeBase64()` normalizes standard→URL-safe. NEVER use `Base64.getUrlDecoder()` on frontend data.
- **Session path handlers**: Accept BOTH old and new field names for backward compatibility (B1-B6).
- **Entity state**: Professional pattern — NfcCard/OAuth2Client use `revokedAt` timestamps, User `isActive` synced from status enum via `@PrePersist/@PreUpdate`.
- **NFC enrollment**: Auto-creates user_enrollments record. Reactivates existing inactive card on re-enrollment.
- **CORS**: api.fivucsas.com, app.fivucsas.com, demo.fivucsas.com, verify.fivucsas.com

## Flyway Migrations (V1-V61)

V1-V15: Core schema | V16: Auth methods/flows | V17: Devices | V24: OAuth2 | V25: Enrollments
V26-V28: Verification pipeline | V29: EMAIL_OTP default | V30: Adaptive MFA (CHOICE steps)
V31: display_order fix | V32: Entity professionalization (revokedAt, expiresAt, verifiedAt)
V33: voice_enrollments table | V34: oauth2_clients.confidential | V35: mfa_sessions.consumed_at
V36: mfa_sessions.client_id | V37: oauth2_clients.tenant_id index | V38: dashboard → confidential=false
V39-V49: TOTP encryption, audit_logs partition, GDPR purge job, tenants.deleted_at
V50: refresh_tokens.family_id (RFC 6749 §10.4 reuse-detection)
V51: shedlock | V52: shedlock TZ fix | V53: forbid hard-delete trigger on users/tenants
V54: phone E.164 normalization | V55: refresh_token hash + dual-read (P1-1)
V56: noop placeholder reserved for refresh-token plaintext-column drop (chain-contiguity)
V57: audit_logs handed to pg_partman — fail-soft when extension missing
     (`RAISE WARNING + RETURN`); explicit opt-out via `app.skip_partman_v57=on` GUC.
     See `/opt/projects/infra/RUNBOOK_AUDIT_LOG_PARTMAN.md`.
V58: oauth2_clients secret-rotation grace window (backs POST `/{id}/rotate-secret`).
V59: backfill audit_logs.tenant_id NULLs + introduce "system" sentinel tenant.
V60: drop refresh_tokens.token plaintext column (hashed wire-format fully active since V55).
V61: audit_logs.tenant_id SET NOT NULL (#99) — self-gating: pre-checks 0 NULLs and
     fails loud, no DEFAULT, metadata-only ALTER on PG12+. Applies on the next rebuild.
V62: tenants.enforce_domain_matching BOOLEAN NOT NULL DEFAULT false — opt-in
     email-domain registration gate. When true, only registrants whose email
     domain is in tenant_email_domains (V44) may join; else graceful (today's
     behaviour). Backs the admin email-domain CRUD + RegisterUserService gate.
V63: tenant_email_domains.verified BOOLEAN NOT NULL DEFAULT false — domain-
     ownership gate for self-service onboarding. Only verified=true domains
     auto-bind new registrants / satisfy enforce_domain_matching. Migration
     backfills ALL pre-existing rows (Marmara etc.) to verified=true so current
     behaviour is unchanged; admin/ROOT CRUD adds are verified=true; only the
     PUBLIC self-service claim is verified=false (flipped later by Round-2 DNS-TXT
     verification or SUPER_ADMIN approval). Backs POST /api/v1/onboarding/register.
V64: DNS-TXT domain verification + default-role-on-join.
     tenant_email_domains.verification_token + verification_requested_at (the
     DNS-TXT challenge state); tenants.default_member_role (role auto-assigned to
     users who join via a verified domain, NULL = seeded USER). All nullable,
     idempotent, no backfill. Backs POST .../email-domains/{domain}/verification
     (returns the TXT record _fivucsas-verify.{domain} =
     "fivucsas-domain-verification={token}") and POST .../{domain}/verify (DNS
     lookup → verified=true on match; 200/422/409). DNS via JNDI behind
     DnsTxtLookupPort (no new dep).
V65-V67: Identity & Account-Linking Phase 1 (identities, identity_emails,
     users.identity_id FK + backfill). Zero behavior change. See
     docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md.
V68: Identity & Account-Linking Phase 3 (Model A) —
     identity_tenant_biometric_consent(identity_id, tenant_id, method?, granted,
     granted_at, revoked_at, UNIQUE(identity_id, tenant_id, method)). Cross-tenant
     / platform-level table (deliberately NOT @Filter(tenantFilter), like
     identities). Backs the per-tenant biometric-consent endpoints + the
     consent-gated cross-tenant verify routing. Does NOT re-key the
     biometric-processor pgvector store — "one template per person" is achieved at
     the api orchestration layer (canonical-enrollment routing). Idempotent
     (CREATE ... IF NOT EXISTS); applies cleanly from V67.

**V34-V60 applied in prod. Last rebuild included V60 (drop refresh_tokens.token plaintext).**

## 2026-05-04 highlights

- **PR #63** — ArchUnit `UserDomainImportBoundaryTest` freezes direct `entity.User`
  imports outside `infrastructure/`/`repository/`/`entity/` (T2.2 implementation;
  prevents drift back into the dual-User-model anti-pattern).
- **PR #64** — `HsKeyRegistry` Spring component holds `Map<String, SecretKey>`
  keyed by `kid`. `JwtService.buildToken` stamps the active kid; `keyLocator()`
  routes verification through `hsKeyRegistry.keyFor(kid)`. Legacy `JWT_SECRET`
  maps to historical kid `hs-2026-04`. Sets up no-logout HS-secret rotation.
- **PR #65** — login edge cases #1/#3/#4/#5/#6/#9 (DELETE `/auth/sessions/{id}`,
  `METHOD_ALREADY_USED` → 409, response carries `currentStep`/`totalSteps`/etc.).
- **PR #66** — DeviceController + 5 call-sites now route credential writes through
  `WebAuthnCredentialService.{saveCredential,updateSignCount}`; new ArchUnit
  `WebAuthnRepoWriteBoundaryTest` blocks future regressions.
- **PR #67** — `/oauth2/userinfo` rejects ID-token replay via `type=oauth2` claim.
- **PR #68** — V57 pg_partman + V56 chain-contiguity placeholder + Testcontainers IT.
- **PR #69** — F15: `Thread.sleep` eliminated from `JwtServiceTest`.
- **PR #70** — `User` entity gets `@SQLDelete` (mirrors `softDelete()` domain method)
  + `@SQLRestriction("deleted_at IS NULL")`. V53 BEFORE-DELETE trigger no longer
  surfaces as 5xx on `userRepository.delete()`. All 9 `findBy*` methods auto-filter
  the GDPR retention window. `findPurgeCandidates` uses `nativeQuery=true`.
- **PR #71 (P0-PROD, merged)** — `RefreshToken` now `implements Persistable<UUID>`
  with explicit `isNew()` flag. Closes the 6 audit-log MFA_STEP_FAILED rows for
  `ahabgu@gmail.com` between 06:34–06:38 UTC on 2026-05-04 (Hibernate was
  treating manually-assigned UUIDs as merge candidates → silent NOOP on insert).

## Operator reality (2026-05-29 update)

- **P1-4 audit-attribution + soft-delete/lazy-proxy sweep DEPLOYED (PR #135,
  main `4229eb4`, prod image `11f0f434`).** New `AuditLogPort.logTenantManagementEvent(
  actorUserId, eventType, tenantId, details)` writes audit rows with a SEPARATE
  actor (`user_id` FK, nulled via `existsById` if not a real user) and resource
  (`resource_id` = the managed tenant, `resource_type` = "TENANT", `tenant_id` =
  the managed tenant). Fixed 8 wrong-actor call sites that passed the TENANT id
  into the `user_id` slot (`ManageTenantService` ×5, `ManageTenantEmailDomainService`
  ×3 add/remove/primary); the 2 DNS-verify calls already passed `actingUserId` and
  now route through the same method. Services resolve the actor via
  `rbacService.getCurrentUserId()` (UUID helper — NOT `getCurrentUser().getId()`,
  which would trip `UserDomainBoundaryTest`); null for self-service onboarding.
  **Soft-delete/lazy-proxy guards** added (force-init in try/catch, fall back to
  null, raw FK id preserved — same idiom as `EnrollmentQueryService`) to
  `UserResponseMapper.toResponse` (/users render, guards `getTenant().getName()`
  when a tenant is soft-deleted), `EnrollmentResponse` (guards `getUser()` on a
  soft-deleted owner), and `UserDataExportService.serializeUser`. Validated live on
  staging: TENANT_UPDATED row now has `user_id`=acting admin, `resource_type`=TENANT,
  `resource_id`/`tenant_id`=managed tenant; /users + /enrollments still 200.
- **P0-1 tenant-isolation defense-in-depth DEPLOYED (PR #134, prod image
  `577acd6b`).** Added the Hibernate `@Filter(tenantFilter)` to the 8 tenant-scoped
  entities that previously relied on controller `currentScope()` only (`AuditLog`,
  `AuthSession`, `MfaSession`, `UserEnrollment`, `VerificationSession`,
  `OAuth2Client`, `UserDevice`, `AuthFlow`; reuses the global `@FilterDef` on
  `User`). Validated off-prod on staging w/ 2-tenant seed: no-header SUPER_ADMIN
  reads scope to HOME (filter overrides controller `tenantScope=ALL`), X-Tenant-ID
  switch partitions correctly, no leak, all 8 endpoints 200. **Behavior change:**
  SUPER_ADMIN no-header now scopes these to HOME (was cross-tenant null), like
  `/users`; web always sends X-Tenant-ID so the UI is unaffected. **AuthFlow is the
  only PATH-scoped list** — the filter intersects to EMPTY when path tenant ≠ active
  X-Tenant-ID; fixed in web-app #126 (`AuthFlowsPage` uses the active tenant for the
  path, also fixing a latent switcher-ignored bug). `CrossTenantIsolationIT` exists
  (RUN_INTEGRATION-gated → P1-1 makes it a CI gate). Staging env (P1-2) at
  127.0.0.1:18080 — see `docs/RUNBOOK_STAGING.md`.
- **Rebuilt 2026-05-29 12:25 UTC** (image `7109c30f`, healthy, boot 24s) — shipped
  PR #115 (two admin 500 fixes) + the merged 2026-05-29 delta (#99 V61, #114 dead
  card-detect proxy removal). **V61 applied** (audit_logs.tenant_id → NOT NULL;
  precondition 0 NULLs verified before the rebuild). Flyway now at V61.
- **PR #115 (two prod admin 500s)** — (1) Auth Flows "Make Default" star hit
  `23505 uq_auth_flow_default`: the dethrone-then-claim in
  `ManageAuthFlowService.updateFlow` now uses `saveAndFlush` so the partial unique
  index slot is freed per-statement before the new default claims it. (2)
  `/enrollments` list 500'd via `EntityNotFoundException` when an enrollment's
  `User` proxy pointed at a soft-deleted/missing row (5 of 37 in prod) — the first
  bad row aborted the whole list. `EnrollmentQueryService.mapEnrollmentToDto` now
  force-inits the proxy in a try/catch and renders null user fields instead.
- **PR #117 (admin gaps, rebuilt 2026-05-29 12:47 UTC, image healthy)** — (1)
  Enrollments list now surfaces the raw `user_id` for soft-deleted owners via a
  read-only `@Column` on `UserEnrollment` (name/email stay null). (2) Set-default
  lockout guardrail: new advisory `GET /tenants/{tid}/auth-flows/{fid}/default-impact`
  → `{activeUsers, usersAtRisk, methods[{method, choice, enrolledUsers, missingUsers}]}`.
  Derives required non-PASSWORD methods from the flow's steps (CHOICE = any-one),
  compares to per-user ENROLLED methods. web-app #114 surfaces it as a warning in
  the "Make Default" dialog. Paired web-app PRs: #114 (enrollment detail page +
  `/enrollments/:id` route + N/A score columns + guardrail dialog) and #115
  (removed the redundant sidebar "FIVUCSAS suite" bar — launcher FAB covers it).
- **SUPER_ADMIN tenant switcher — UNIFIED on `X-Tenant-ID` (branch
  `feat/2026-05-29-superadmin-tenant-switcher-unified`, PR open, NOT merged):**
  Supersedes the earlier partial `X-Active-Tenant` attempt (#129). The switcher
  now uses ONE header — the standard `X-Tenant-ID` — to scope BOTH multi-tenancy
  layers at once for a SUPER_ADMIN:
  1. the Hibernate `tenantFilter` (Users/Roles, via `TenantContextFilter` +
     `TenantBindFromAuthFilter`), and
  2. `TenantScopeResolver.currentScope()` (Audit-Logs/Sessions/Devices/Enrollments
     + the guest endpoints).
  - **403 root cause + fix.** With a foreign `X-Tenant-ID` active, the Hibernate
    `tenantFilter` was scoping the SUPER_ADMIN's OWN identity lookup
    (`findByEmail`) to the foreign tenant. A ROOT user's row lives in the system
    tenant (`000…000`), so it got filtered out → `getCurrentUser()` /
    `loadUserByUsername()` returned empty → `@PreAuthorize` saw NO authorities →
    Spring `403 "Access Denied"` on the very endpoint that drives the switcher.
    **Fix:** caller self-resolution now runs through new
    `infrastructure.multitenancy.TenantFilterBypass` (clears `TenantContext` +
    disables `tenantFilter` for the lookup, restores after — so
    `TenantHibernateAspect` does not re-enable it on the inner repo call). Wired
    into `RbacAuthorizationService.getCurrentUser` AND
    `CustomUserDetailsService.loadUserByUsername`. Identity is keyed by unique
    email (a caller can only ever resolve THEIR OWN row), and the
    `@SQLRestriction("deleted_at IS NULL")` soft-delete guard is untouched — so
    this is not a cross-tenant leak. Defense-in-depth: `Role.tenantFilter`
    condition widened to `(tenant_id = :tenantId OR tenant_id IS NULL)` so global
    role DEFINITIONS (SUPER_ADMIN/SYSTEM) stay visible regardless of active tenant
    (grants are via `user_roles`, so still no leak).
  - **Unified scope.** `TenantScopeResolver.currentScope()` reads `X-Tenant-ID`
    (canonical) with `X-Active-Tenant` kept as a back-compat alias (canonical
    wins if both present). SUPER_ADMIN + valid header → that tenant; no header →
    `null` (cross-tenant, preserving today's `null`-handling controllers; the web
    switcher always sends the header, defaulting to home). For ANY non-ROOT caller
    BOTH headers are IGNORED (home tenant only) — no privilege/tenant escalation.
  - **`isCrossTenantAdmin()`** (new) = the SUPER_ADMIN CAPABILITY, independent of
    the active selection. `TenantController.getAllTenants` (the switcher's own
    dropdown source) now uses it instead of `isUnrestricted()`, so selecting a
    tenant doesn't collapse the dropdown to one entry.
  - **`/users` consistency.** `ManageUserService.resolveTenantScope()` now
    delegates to `TenantScopeResolver.currentScope()` (was: return `null` for any
    SUPER_ADMIN + lean on the implicit Hibernate filter). Result: list/count/search
    all scope explicitly to the selected tenant (home by default).
  - Security tests: `TenantFilterBypassTest`, `RbacAuthorizationServiceTest`,
    extended `TenantScopeResolverTest` (X-Tenant-ID + precedence + isolation), and
    `TenantSwitcherIsolationIT` (Testcontainers, `RUN_INTEGRATION=true`) pinning
    the 403 fix + TENANT_ADMIN cross-tenant isolation end-to-end.
  - **Revoke a PENDING guest invitation** — new `POST /api/v1/guests/invitations/{invitationId}/revoke`
    (gate `@rbac.isTenantAdmin() or @rbac.hasPermission('guest:revoke')` + tenant-scope
    guard via `TenantScopeResolver.canAccessTenant`). Calls
    `GuestLifecycleService.revokeInvitation(invitationId, actorUserId)`: PENDING/EXPIRED→REVOKED,
    already-REVOKED→idempotent no-op, ACCEPTED→409 (direct to user-revoke), missing→404.
    Audited as `GUEST_INVITATION_REVOKED` with userId = acting admin's user id (or null),
    NEVER the invitation/tenant id. The existing `POST /api/v1/guests/{guestUserId}/revoke`
    (ACCEPTED guests) is unchanged.
- **OPEN gap:** guest invitations send NO email (`GuestLifecycleService.createInvitation`
  has no email call; `EmailService` only does `sendOtp`). Accept endpoint + token
  exist but the guest can't receive the link → can't log in. Needs EmailService
  wiring + a frontend accept-invite page. FACE/VOICE enrollment quality/liveness
  scores are also never persisted to `user_enrollments`.
- Note: the parent submodule pointer for identity-core-api drifts STALE in this
  repo's workflow (read `606f1f4` while deployed was newer). Verify deployed state
  by the running container / Flyway version, not the parent pointer.
- V60 (drop refresh_tokens.token plaintext) applied in prod. Prod has been rebuilt
  since the 2026-05-04 pending note — V56 through V60 all applied.
- pg_partman (V57) is fail-soft. `ALTER DATABASE identity_core SET app.skip_partman_v57='on'`
  is available for explicit opt-out if partman extension is absent.
- **`APP_SECURITY_JWT_AUDIENCE` MUST be non-blank in `.env.prod`** (set to `fivucsas-api`).
  Since the JWT-aud bundle (2026-05-12), the `prod` profile fails fast on boot with
  "CRITICAL SECURITY ERROR: ...jwt.audience is blank" if it's empty. NOTE: an *empty*
  `APP_SECURITY_JWT_AUDIENCE=` in `.env.prod` OVERRIDES the `:fivucsas-api` default in
  `application-prod.yml` — leaving the var blank is worse than omitting it. This crash-looped
  prod for ~11 min on 2026-05-28 during the rebuild that first shipped the enforcement. The
  minter and parser use the same value, so keep them in lockstep if you ever change it.
- **Docker builds:** `mvn dependency:go-offline` is best-effort (a purged upstream
  `jackson-databind:*-SNAPSHOT` in the transitive closure can make it miss); `mvn package`
  resolves via the `jackson-bom` pin and is authoritative. A go-offline miss does not fail the build.

## Cross-Repo Dependencies

- **biometric-processor** (Python/FastAPI, port 8001) — internal Docker network only, `X-API-Key` header
- **web-app** (React) consumes this API
- **SMTP**: `smtp.hostinger.com:587`, sender `info@fivucsas.com`, creds in `.env.prod`

See TODO.md for integration audit (49 items).
