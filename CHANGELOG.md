# Changelog - Identity Core API

## [Unreleased]

### 2026-06-07 — Test-suite green-up + Turkish-locale & boundary hardening

Behavior-preserving test + boundary fixes. **No production runtime behavior changes;
no DB migration; no security/crypto semantics altered.** Full offline unit/slice +
ArchUnit suite green: `mvn -o test` → **1648 run, 0 failures, 0 errors, 67 skipped**
(the 67 skipped are Testcontainers/DB integration tests, not runnable with Docker off).

- **NFC serial — Turkish-locale casing fix.** `domain.model.NfcSerial` canonicalize
  now upper-cases with `Locale.ROOT` instead of the JVM default locale. Under the
  `tr_TR` locale (the build/runtime default here), bare `toUpperCase()` maps `i → İ`
  and would corrupt a hex serial / break `matches`/`valueOf`-style comparisons. The
  canonical stored form (UPPER-hex, no separators) is now locale-independent so a
  mobile-enrolled card still matches a web verify regardless of server locale.
- **OAuth2 token mint routed off `entity.User` (ArchUnit boundary).** OAuth2 token
  minting no longer imports the `entity.User` JPA type directly; it goes through a new
  `OAuth2TokenMintPort` (application input port) implemented by
  `infrastructure/oauth2/OAuth2TokenMintAdapter`. This satisfies the
  `UserDomainImportBoundaryTest` / `UserDomainBoundaryTest` ArchUnit rules (no
  `entity.User` imports outside `infrastructure/`/`repository/`/`entity/`) and keeps the
  dual-User-model anti-pattern from drifting back. No change to minted token contents.
- **WebAuthn test fix — `completeEnrollment` → `autoBindEnrollment` rename
  reconciliation.** `WebAuthnCredentialService.autoCompleteWebAuthnEnrollment` was
  migrated to call the idempotent, own-transaction `ManageEnrollmentUseCase.autoBindEnrollment(userId, methodType)`
  (the create-if-missing upsert that fixed the first-time-fingerprint
  `UnexpectedRollbackException` / "Beklenmeyen bir hata"), but `WebAuthnCredentialServiceTest`
  still verified/stubbed the removed 3-arg `completeEnrollment(userId, methodType, "{}")`.
  Three tests were red (2 "Wanted but not invoked" + 1 `UnnecessaryStubbingException`):
  `platformTransportTriggersFingerprintEnrollment`, `roamingTransportTriggersHardwareKeyEnrollment`,
  `swallowsEnrollmentFailure`. Fixed the **test** to assert the current production API
  (`autoBindEnrollment(userId, methodType)`); production code left unchanged. The
  separate `ManageEnrollmentUseCase.completeEnrollment(...)` overloads remain in use by
  the start→complete enrollment flow and are unaffected.

### 2026-06-03 — Face-enrollment flag-consistency (fixes the "enrolled-but-412" class)

Several enroll paths persisted a FACE embedding in the biometric-processor store
but failed to flip the denormalized `users.is_biometric_enrolled` boolean that
`/biometric/verify` gates on, so affected users got HTTP **412 BiometricNotEnrolled**
on verify despite a real template. Fixed the write paths + added a reconciler to
repair already-inconsistent rows. **No production DB was modified by this change.**

- **Atomic multi-image enroll.** `POST /biometric/enroll/multi` now runs the bio
  enroll + score recording + `is_biometric_enrolled` flag-flip inside ONE
  `@Transactional` service method (`EnrollBiometricService.enrollFaceMulti`),
  mirroring the single-image `execute()`. The controller previously made two
  loose, non-transactional calls and flipped the flag on a fragile
  `!Boolean.FALSE.equals(success)` check; success is now
  `Boolean.TRUE.equals(success)` (with a tolerant `"true"` string fallback) so a
  missing/null/ambiguous result never flips the flag speculatively. Response
  contract unchanged.
- **Legacy `submitEnrollment` flag-flip.** `POST /enrollment/submit` used to
  enroll the embedding but never flip the flag (guaranteed-412 users). It now
  routes the flip through the canonical, idempotent, transactional
  `EnrollBiometricUseCase.markBiometricEnrolled`; the existing
  `recordBiometricScores` call already creates/completes the `user_enrollments`
  FACE row, matching the canonical path.
- **Reconciliation mechanism (code only — NOT run against prod).** New
  ROOT-gated `POST /api/v1/admin/biometric/reconcile-enrollment-flags`
  (`BiometricReconcileAdminController` → `BiometricEnrollmentReconciler`),
  **dry-run by default** (`apply=true` to write). It scans users with the flag
  `false`, and for each one the bio store CONFIRMS holds an embedding
  (`BiometricServicePort.hasEnrollment(userId, tenant)`, backed by the existing
  bio `/embeddings/export`), flips `false → true`. Idempotent, fail-closed (any
  bio error → no flip), and never sets a flag to `false` (cannot lock anyone out).
- **Verify gate TODO.** Added a code TODO in `VerifyBiometricService` noting the
  better long-term fix (gate on actual embedding presence, not the denormalized
  boolean). The security-sensitive verify gate is **not** changed in this PR.

### 2026-05-30 — Config-driven login engine (task #16, A+B+C+F+G)

**Ships DARK — feature-flagged, default OFF, instantly revertible without a
redeploy.** `ConfigDrivenLoginPolicy` gates the entire behavior change:
- `app.auth.config-driven-login` (env `APP_AUTH_CONFIG_DRIVEN_LOGIN`, default
  **false**) — master switch. When OFF, login is **byte-identical to the legacy
  password-first behavior**: the hard password gate stays, usernameless entry
  points (passkey/QR) mint tokens directly, and `login-config` advertises the
  single-step PASSWORD shape so the UI behaves exactly as today.
- `app.auth.config-driven-login-tenants` (env
  `APP_AUTH_CONFIG_DRIVEN_LOGIN_TENANTS`, CSV of tenant UUIDs) — per-tenant
  **canary**: enable the new engine for one tenant in prod before the global
  flip. Invalid UUIDs are skipped with a warn (never widens rollout / crashes).
- Rollout: dark → staging soak → canary one tenant → global. Kill = unset the
  flag (no rebuild/rollback).

When ENABLED, login is driven by the tenant's default `APP_LOGIN` flow. The hard
pre-flow password gate in `AuthenticateUserService` is replaced by the tenant's
configured Layer-1 method (PASSWORD verified inline as step 1 when Layer-1
includes it — observable behavior UNCHANGED for PASSWORD-first tenants;
otherwise the `MfaSession` starts at step 1 with that identifier-first method
and `VerifyMfaStepService` runs it). Backward-compatible: PASSWORD-first flows
(e.g. Marmara) and the cross-tenant isolation ITs are unchanged/green.

- **A — data model (V73).** New `AuthMethodType` PASSKEY + APPROVE_LOGIN
  (seeded), new `auth_methods.supports_usernameless` (TRUE for
  PASSKEY/APPROVE_LOGIN/QR_CODE); `chk_auth_method_type` widened (full V28 list
  preserved). PASSKEY = discoverable mode of WebAuthn; APPROVE_LOGIN =
  number-matching mode of the QR cross-device-approval method (G).
- **B — usernameless INTO the flow.** `DeviceController.passkeyAuthenticate`,
  `ApproveLoginService.decide`, and `QrSessionService.approveSession` no longer
  mint tokens the instant the factor verifies. They resolve the user, then
  bridge through the new `UsernamelessLoginFlowService` into the tenant default
  `APP_LOGIN` flow: if Layer-2+ steps remain → open an `MfaSession`
  (currentStep=2, completedMethods=[that Layer-1 method]) and return
  `MFA_PENDING`; mint only when the flow is 1-step/none. `amr` accumulates the
  Layer-1 method (PASSKEY→`hwk`, APPROVE_LOGIN/QR_CODE→`mca`) plus later steps.
  QR approve also now mints a REAL rotating refresh token (was a placeholder
  UUID). When the engine is OFF, QR/passkey/approve-login mint exactly as before
  (QR keeps its legacy `JwtService` + placeholder-UUID path).
- **C — `GET /api/v1/auth/login-config?tenantId=<uuid>`** (unauthenticated,
  permitAll). Returns the FROZEN public login contract — `{tenantId, tenantName,
  layer1:{methods:[{type,usernameless,requiresEnrollment}],identifierRequired},
  totalSteps, laterSteps:[{order,methods}]}` — with NO internal IDs. No default
  flow → implicit single-step PASSWORD config.
- **F — default-impact (`computeDefaultImpact`).** Usernameless Layer-1 factors
  no longer count as a lockout risk (the factor proves its own enrollment); new
  `noRecoveryWarning` field flags a flow with no PASSWORD step where every
  required step is a single usernameless factor with no alternative. (Admin
  advisory analysis — not gated by the login flag.)
- **Reversibility.** Migration V73 is ADDITIVE only (new enum values + a
  `supports_usernameless` column defaulting false + a widened CHECK); it
  alters/drops no existing columns or rows, so a roll back to the prior image
  keeps working. Combined with the default-OFF flag, the change ships with zero
  runtime effect until an operator opts a tenant in.
- ArchUnit `UserDomainBoundaryTest` baseline refrozen for the new
  `UsernamelessLoginFlowService` (entity-`User` use mirrors `AuthenticateUserService`).

### 2026-05-30 — Stabilize-&-harden backlog (P1-1 + P1-5, DEPLOYED)

- **P1-1 (PR #155/#156)** — cross-tenant isolation ITs promoted to a REQUIRED CI
  gate: the `integration-tests` job runs `-Dtest='*IntegrationTest,*IT'`, blocks
  (no `continue-on-error`), and asserts they executed. 3 unit tests fixed to
  unblock `needs: test`. Operator must add the `Integration tests (Testcontainers)`
  required status check in branch protection.
- **P1-5 (PR #157, DEPLOYED)** — Flyway chain made DR-safe from a fresh database:
  V29 rewritten to resolve Default-Login flow + EMAIL_OTP by natural keys (was
  prod-only hardcoded UUIDs); fixed V40 pkey collision + V40/V41
  `COMMENT 'a'||'b'` syntax. Chain now applies 71/71 from an empty DB. Shipped via
  a one-time `flyway repair` (validate-on-migrate=true). See
  `docs/RUNBOOK_FLYWAY_V29_REPAIR.md`.

### 2026-05-29 — DNS-TXT email-domain verification + default-role-on-join (V64)

Backend only (frontend DNS-verify UI ships separately).

- **DNS-TXT domain-ownership verification.** A tenant admin can now PROVE
  ownership of a claimed email domain via a DNS TXT record, flipping
  `tenant_email_domains.verified` to `true`. Only verified domains auto-bind other
  registrants / satisfy `enforce_domain_matching` (V62) / lift onboarding trial
  caps. Two NEW endpoints (gated `@rbac.isTenantAdmin() and @rbac.canAccessTenant`,
  ROOT cross-tenant):
  - `POST /api/v1/tenants/{tenantId}/email-domains/{domain}/verification` —
    generates (or returns the existing) token and returns the TXT record to
    publish. Record name `_fivucsas-verify.{domain}`, type `TXT`, value
    `fivucsas-domain-verification={token}`. Idempotent.
  - `POST /api/v1/tenants/{tenantId}/email-domains/{domain}/verify` — performs a
    DNS TXT lookup; on a match sets `verified=true` and clears the token. Returns
    `200 {verified:true}`, `422 {verified:false, reason:"RECORD_NOT_FOUND"}`
    (absent/mismatch), or `409 {verified:false, reason:"NO_CHALLENGE"}` (no token
    yet). DNS lookup uses the JDK JNDI DNS provider behind a `DnsTxtLookupPort`
    (no new dependency); NXDOMAIN/timeouts degrade gracefully to not-verified.
    Verification is audit-logged under the acting admin's user id (or null), never
    the tenant id (avoids `audit_logs_user_id_fkey`).
- **default-role-on-join (in-platform JIT).** New per-tenant
  `tenants.default_member_role` (settable via `PUT /api/v1/tenants/{id}`, surfaced
  in the tenant response). When a registrant auto-joins a tenant via a VERIFIED
  email domain, `RegisterUserService` assigns that role (falls back to the seeded
  `USER` role if unset). Best-effort — never rolls back registration. NOTE: this
  scopes "JIT" to in-platform auto-provisioning; true external-IdP/SSO JIT does not
  apply (this platform IS the IdP, not a federation consumer).
- **Migration V64** — `tenant_email_domains.verification_token` +
  `verification_requested_at`; `tenants.default_member_role`. All nullable,
  idempotent (`ADD COLUMN IF NOT EXISTS`), no backfill (defaults preserve current
  behaviour).
- Verified-only auto-bind reuses `findByIdEmailDomainIgnoreCaseAndVerifiedTrue`
  (V63). ArchUnit `UserDomainBoundaryTest` baseline shrank (RegisterUserService
  `entity.User` call surface reduced); default-role assignment routes through a
  new `MemberRoleAssignmentPort` infrastructure adapter to keep the boundary clean.

### 2026-05-29 — Admin 500 fixes, guest-invite email, SUPER_ADMIN /auth/me, tenant email-domain management (5 PRs)

Squash-merged to `main`:

- **PR #115** `fix/admin-500s-2026-05-29` — two production admin 500s:
  - Auth Flows "Make Default" hit `23505 uq_auth_flow_default` (the partial unique
    index). `ManageAuthFlowService` now dethrones the current default via
    `saveAndFlush` so the index slot is freed per-statement before the new default
    claims it.
  - `GET /enrollments` 500'd via `EntityNotFoundException` when an enrollment's
    `User` proxy pointed at a soft-deleted/missing row — the first bad row aborted
    the whole list. `EnrollmentQueryService` now force-inits the proxy in a
    try/catch and renders null user fields instead.
- **PR #117** `feat/enrollment-admin-gaps-2026-05-29` — admin visibility gaps:
  - Enrollments list now surfaces the raw `user_id` for soft-deleted owners (name
    and email stay null).
  - NEW advisory endpoint `GET /api/v1/tenants/{tenantId}/auth-flows/{flowId}/default-impact`
    — set-default lockout guardrail. Returns
    `{activeUsers, usersAtRisk, methods[{method, choice, enrolledUsers, missingUsers}]}`,
    derived by comparing each flow's required non-PASSWORD methods (CHOICE = any-one)
    against per-user ENROLLED methods. Surfaced as a warning in the web-app
    "Make Default" dialog.
- **PR #119** `feat/guest-invite-email` — guest invitations now **send email**.
  `EmailService.sendGuestInvitation` delivers the accept link (built from the new
  `app.frontend-base-url` config); previously the accept endpoint and token existed
  but the guest never received the link. NEW endpoint
  `POST /api/v1/guests/{invitationId}/resend` re-sends a pending invitation.
- **PR #120** `fix/super-admin-auth-me-500` — `GET /auth/me` no longer 500s for
  `SUPER_ADMIN`. The domain `Role` model no longer requires a tenant for global
  system roles, so `SUPER_ADMIN` (whose `tenant_id` is NULL) maps cleanly.
- **PR #121** `feat/tenant-email-domain-management` — tenant email-domain
  management:
  - NEW endpoints `GET /api/v1/tenants/{tenantId}/email-domains`,
    `POST /api/v1/tenants/{tenantId}/email-domains`,
    `DELETE /api/v1/tenants/{tenantId}/email-domains/{domain}`, and
    `PATCH /api/v1/tenants/{tenantId}/email-domains/{domain}/primary`.
  - **V62** `V62__tenants_enforce_domain_matching.sql` — adds
    `tenants.enforce_domain_matching BOOLEAN NOT NULL DEFAULT false` (opt-in).
    When enabled, `RegisterUserService` rejects registrants whose email domain is
    not in the tenant's allowed domains with HTTP 422; when disabled, registration
    is unrestricted (today's behaviour).

### 2026-05-11 — Flyway V58–V60 (ops / DB hygiene)

- **V58** `V58__oauth2_clients_secret_rotation.sql` — adds `previous_secret_hash`
  + `previous_secret_expires_at` columns to `oauth2_clients`. Backs the new
  `POST /api/v1/oauth2/clients/{id}/rotate-secret` endpoint: after rotation the
  old secret remains valid for 24 h so deployed integrations can roll over without
  downtime.
- **V59** `V59__backfill_audit_logs_tenant_id.sql` — backfills `audit_logs.tenant_id`
  NULLs (140/1107 rows in prod, 12.6%) and introduces a "system" sentinel tenant
  as the fallback owner for system-generated events. Prod NULL count 140 → 0 after
  apply.
- **V60** `V60__drop_refresh_tokens_token_plaintext.sql` — drops the
  `refresh_tokens.token` plaintext column. The hashed wire-format
  `<id>.<secret>` / `token_secret_hash` has been the live path since V55
  (2026-05-02); V56 was a reserved no-op placeholder ensuring chain contiguity.
  Prod rebuilt and healthy with V60 applied.

### Operator notes (updated 2026-05-28)

- **V60 applied in prod.** The 2026-05-04 "rebuild PENDING" note is resolved —
  prod has been rebuilt and V56 through V60 are all applied and healthy.
- V57 (pg_partman) is fail-soft, so a rebuild is safe even without
  `pg_partman` installed in the postgres image — the migration logs a
  `RAISE WARNING` and returns. To opt out explicitly:
  `ALTER DATABASE identity_core SET app.skip_partman_v57='on';`
- Senior DB review (`SENIOR_DB_REVIEW_2026-05-04.md`) Appendix C lists 7 prod
  queries that need Hetzner SSH to answer.

### 2026-05-04 — Quality + senior-DB-review wave (9 PRs)

Squash-merged to `main`:

- **PR #63** `arch/user-domain-boundary-archunit` (`432b4d3`) — ArchUnit guard
  freezing direct `entity.User` imports outside `infrastructure/`/`repository/`/
  `entity/`. Implements T2.2 from `ROADMAP_OPTIMIZED_2026-05-02.md`.
- **PR #64** `feat/jwt-kid-registry` (`2d958c5`) — `HsKeyRegistry` component +
  `JwtService` kid stamping + JWS `keyLocator` per-kid lookup. Backward-compat:
  legacy `JWT_SECRET` maps to historical kid `hs-2026-04` automatically.
- **PR #65** `fix/login-edge-cases-2026-05-04` (`d224ad1`) — login edge cases
  #1, #3, #4, #5, #6, #9 from the 2026-04-24 audit:
  - #1/#6 pre-flight enrollment check on `ExecuteAuthSessionService.startSession`.
  - #3/#9 new `DELETE /api/v1/auth/sessions/{sessionId}` (idempotent 204/404).
  - #4 `METHOD_ALREADY_USED` returns 409 (was 400).
  - #5 error responses carry `currentStep`, `totalSteps`, `expectedMethod(s)`,
    `completedMethods`, `nextAction`.
- **PR #66** `fix/devicecontroller-webauthn-service-boundary` (`e986609`) —
  `DeviceController` + `HardwareKeyAuthHandler` + `FingerprintAuthHandler` +
  `WebAuthnVerifySupport` now route credential writes through
  `WebAuthnCredentialService.{saveCredential,updateSignCount}`. New ArchUnit
  `WebAuthnRepoWriteBoundaryTest` blocks future regressions.
- **PR #67** `chore/security-userinfo-typecheck` (`2b49bd5`) — `/oauth2/userinfo`
  now requires `type=oauth2` claim, rejecting ID-token replay.
- **PR #68** `feat/audit-log-pg-partman-migration` (`d95425c`) — V57 pg_partman
  with monthly partitions, premake=12, retention 24 months, **fail-soft when
  extension missing** (`RAISE WARNING + RETURN`). New
  `V56__noop_reserved_for_refresh_token_plaintext_drop.sql` placeholder for chain
  contiguity. Testcontainers IT against `postgres:16-alpine`. Operator runbook at
  `/opt/projects/infra/RUNBOOK_AUDIT_LOG_PARTMAN.md`.
- **PR #69** `chore/test-f15-deterministic-clock` (`70036a5`) — F15: `Thread.sleep`
  eliminated from `JwtServiceTest` (negative-expiration mint + `jti` uniqueness).
- **PR #70** `fix/user-soft-delete-jpa-restriction` (`1e23ef0`) — `User` entity
  gets `@SQLDelete` (mirrors `softDelete()` domain method) + `@SQLRestriction
  ("deleted_at IS NULL")`. V53 BEFORE-DELETE trigger no longer 5xx's on
  `userRepository.delete()`. All 9 `findBy*` methods auto-filter the GDPR
  retention window. `findPurgeCandidates` switched to `nativeQuery=true` so
  `SoftDeletePurgeJob` can still see deleted rows. New
  `UserSoftDeleteAnnotationsTest` mirrors `TenantSoftDeleteAnnotationsTest`.
  Closes SENIOR_DB_REVIEW_2026-05-04 §P0-2 + §P0-3.
- **PR #71 (P0-PROD)** `fix/refresh-token-persistable-isnew` (`a77c844`) —
  `RefreshToken` now `implements Persistable<UUID>` with an explicit `isNew()`
  flag toggled in `@PrePersist`. Hibernate had been treating manually-assigned
  UUIDs as merge candidates and silently NOOP-ing the insert; this surfaced as
  6 `MFA_STEP_FAILED` audit-log rows for `ahabgu@gmail.com` between 06:34–06:38
  UTC on 2026-05-04. Rebuild required to take effect in prod.

### Operator notes (2026-05-04 wave)

- PRs #63–#71 shipped. The 2026-05-04 rebuild referenced here has since completed
  (see the 2026-05-11 section above for current prod state).
- Senior DB review (`SENIOR_DB_REVIEW_2026-05-04.md`) Appendix C lists 7 prod
  queries that need Hetzner SSH to answer.

### Docs — 2026-04-26 (iOS / macOS scope dropped)
- Forward-looking "Sign in with Apple" social auth dropped from `README.md` Future section. iOS / iPadOS / macOS permanently out of scope — Sign in with Apple requires Apple Developer Program enrollment, and no Apple hardware/account is available. Google social auth remains in scope. macOS dev-environment Redis install instructions are unaffected (developer environment guidance, not product scope).

### Changed
- **Auth flows: any AuthMethod can be step[0].** Removed the hardcoded
  `PASSWORD_MANDATORY_OPERATIONS = {APP_LOGIN, API_ACCESS}` rule from
  `ManageAuthFlowService` and `ExecuteAuthSessionService`. Tenants can now
  configure any `AuthMethodType` as the first step of any operation type
  (e.g. a passwordless `FACE -> TOTP` APP_LOGIN flow). Structural validation
  is retained: a flow must have ≥1 step, exactly one step with
  `stepOrder == 1`, a non-null `AuthMethod` on that step, and unique
  `stepOrder` values. **Backward-compat note:** existing tenants are
  unaffected because the V29 seed still provisions `PASSWORD`-first flows.
  The legacy `/auth/login` endpoint continues to enforce PASSWORD-first
  internally (it is a password-specific endpoint by design); flexible flows
  must be consumed via `/auth/sessions/start` + `/auth/sessions/{id}/steps/{n}`.
  Files: `application/service/ExecuteAuthSessionService.java`,
  `application/service/ManageAuthFlowService.java` and matching unit tests.

### Security
- **BE-H1 — JWT signing: dual-algorithm coexistence (HS512 + RS256).**
  OIDC best practice is asymmetric (RS256) so relying parties can verify ID
  tokens offline via JWKS without sharing the HS512 secret. This change ships
  the RS256 key infrastructure alongside the legacy HS512 secret:
  - New `RsaKeyProvider` loads an RSA 2048 key pair from
    `JWT_RSA_PRIVATE_KEY_PEM` / `JWT_RSA_PUBLIC_KEY_PEM` (fail-fast in prod;
    auto-generates + logs the PEMs once in dev/test profile).
  - `JwtService` now attaches a `kid` header on every mint (`hs-2026-04` for
    HS512, `rs-2026-04` for RS256) and uses a `keyLocator` to verify by kid.
    Legacy tokens without a kid continue to validate against HS512 for
    backward compatibility. Unknown kids are rejected with a SignatureException.
  - Sign-time algorithm is selected by `fivucsas.jwt.default-algo`
    (default `HS512` — **intentionally unchanged** during the coexistence
    window; flip to `RS256` after a couple of days of soak via
    `JWT_DEFAULT_ALGO=RS256`).
  - `/.well-known/jwks.json` now publishes the RSA public key
    (kty=RSA, alg=RS256, kid, n, e). HS512 never goes in JWKS by definition.
  - `/.well-known/openid-configuration` advertises both algs in
    `id_token_signing_alg_values_supported`.
  - Config: new `fivucsas.jwt.*` block in `application.yml`,
    new `JWT_DEFAULT_ALGO` / `JWT_RSA_KID` / `JWT_RSA_{PRIVATE,PUBLIC}_KEY_PEM`
    entries in `.env.example` with an `openssl genrsa -out jwt_rs256.pem 2048`
    generator hint.
  - Tests: 7 new (`JwtDualAlgoTest` ×5, `OpenIDConfigControllerTest` ×2);
    existing `JwtServiceTest` (16) rewired for the new 2-arg constructor.
  Files: `security/RsaKeyProvider.java` (new), `security/JwtService.java`,
  `controller/OpenIDConfigController.java`, `resources/application.yml`,
  `.env.example`.
- **BE-H3 — TOTP shared secrets encrypted at rest (AES-GCM-256).**
  `users.two_factor_secret` previously stored plaintext; now encrypted via new
  `TotpSecretCipher` (KEK from `FIVUCSAS_TOTP_ENC_KEY`, base64 32 bytes) and
  written in format `enc:v1:<base64(iv||ct||tag)>`. Service refuses to boot
  when the KEK is missing/malformed — no silent plaintext fallback. All read
  sites (`AuthController.resolveTotpSecret`, `TotpAuthHandler.resolveTotpSecret`,
  `OtpController.getTotpStatus`) apply dual-read: legacy plaintext returned
  unchanged, `enc:v1:` values decrypted. Writes always encrypt. Redis cache
  continues to hold plaintext (ephemeral, not at-rest). Flyway V39 is a
  placeholder; companion `TotpSecretMigrator` CommandLineRunner (gated by
  `fivucsas.totp.migrate-on-boot=true`, default OFF) re-encrypts legacy rows
  during a maintenance window. `.env.example` documents `openssl rand -base64
  32` generation. AUDIT_2026-04-19.

### Added
- **IN-H5 — `audit_logs` range-partitioned by `created_at` (monthly).**
  New Flyway migrations `V40__partition_audit_logs.sql` and
  `V41__audit_logs_partition_maintenance.sql` address AUDIT_2026-04-19 finding
  IN-H5 (unpartitioned audit_logs growing without bound). V40 renames the
  existing table to `audit_logs_legacy`, creates a new `audit_logs`
  partitioned by range on `created_at`, pre-creates monthly partitions
  2026-01..2026-06, and attaches the legacy table as a historical partition
  bounded by its `min(created_at)` and `2026-01-01`. V41 adds the
  `ensure_audit_logs_partition(target_month date)` helper for monthly cron.
  **Semantic change:** primary key becomes `(id, created_at)` — required by
  Postgres for partitioned tables; application treats `id` as the logical
  key so no code change needed. Views `v_recent_audit_logs`,
  `v_slow_operations`, `mv_audit_statistics`, and the V8 request-id trigger
  are recreated against the new root.

### Deploy checklist — V40/V41 (maintenance window required)
- Staging validation:
  1. `docker compose exec postgres psql -U $DB_USER $DB_NAME -c "SELECT COUNT(*) FROM audit_logs;"` (record row count).
  2. Run Flyway against staging DB with production-parity data.
  3. Verify: `\d+ audit_logs` shows `Partitioned table` and 7 partitions (6 monthly + `audit_logs_legacy`).
  4. Verify row count unchanged; sample `INSERT` into `audit_logs` lands in the correct monthly partition.
  5. Check RLS still blocks cross-tenant reads; `v_recent_audit_logs` returns rows.
- Production rollout:
  1. Schedule a maintenance window (RENAME takes ACCESS EXCLUSIVE — expect a brief write stall on audit writes).
  2. Deploy the identity-core-api container; Flyway will apply V40 + V41 on startup.
  3. Monitor logs for `RAISE NOTICE` outputs from the DO blocks.
  4. Add cron on the Postgres host:
     `0 3 25 * * psql "$PG_URL" -c "SELECT ensure_audit_logs_partition(date_trunc('month', now() + interval '2 months')::date);"`
- Rollback (pre-deploy only): delete V40/V41 files; post-deploy rollback requires detach + rename back (document only).

## [2026-04-19] Audit remediation

Targeted backend + infra fixes from the 2026-04-19 comprehensive audit
(`/opt/projects/fivucsas/docs/audits/AUDIT_2026-04-19.md` — Audit 1, Audit 5).
No Flyway migration, no secret rotation, no container restart.

### Fixed
- **BE-H2 — `GET /oauth2/authorize` (authenticated branch) hardening.**
  The GET branch minted codes with no PKCE enforcement for public clients, no
  `user.tenant == client.tenant` guard, and `codeChallengeMethod != S256` went
  unchallenged. Shared PKCE + tenant checks are now extracted into
  `OAuth2Controller.validateAuthorizeRequest()` and invoked from both the GET
  branch and `POST /authorize/complete`. Happy path for already-correct clients
  is unchanged. `OAuth2Controller.java`.
- **BE-M1 — OAuth2Service Redis auth-code metadata → JSON.** Payload switched
  from pipe-delimited to Jackson JSON. Read side prefers JSON, falls back to
  the legacy pipe split for in-flight codes and logs a one-shot warn. The pipe
  fallback is scheduled for removal after deploy + 15 min (AUTH_CODE_TTL 10m +
  5m margin) — TODO note dated 2026-04-19 in the file.
  `OAuth2Service.java:125-145`.
- **BE-M2 — confidential client hard-reject.** `exchangeCode` previously
  logged a warn and fell through to the public-client code path when a
  confidential client arrived without a `client_secret` and without a PKCE
  verifier. It now throws a new `OAuth2Exception(401, "invalid_client",
  "client_secret required for confidential client")`; the controller catch
  maps the status verbatim. `OAuth2Service.java:201-210`, new
  `domain/exception/OAuth2Exception.java`.
- **BE-M5 — refresh-token rotation no longer revokes all devices.**
  `RefreshTokenService.createRefreshToken` dropped the unconditional
  `revokeAllUserTokens` call. Rotation via `rotateRefreshToken` already
  revokes the specific token being replaced; other devices stay signed in.
  Invariant documented in the method body. `RefreshTokenService.java:28-48`.
- **IN-H2 — admin-whitelist attached.** Added a new file-based router
  `fivucsas-api-admin` in `/opt/projects/infra/traefik/config/dynamic.yml`
  that matches `api.fivucsas.com` + PathPrefix(`/swagger-ui`, `/v3/api-docs`,
  `/actuator`) + Path(`/swagger-ui.html`), carrying
  `admin-whitelist@file,secure-headers@file,rate-limit@file` and routing to
  `identity-api@docker`. Traefik's longer-rule-wins precedence means the
  public docker-label router (Host only) still serves `/oauth2/**`,
  `/auth/**`, `/api/v1/**` unchanged. Traefik not reloaded per instructions.

### Added
- `com.fivucsas.identity.domain.exception.OAuth2Exception` — carries an
  `HttpStatus` + OAuth2 `error` code so the token endpoint can return 401
  `invalid_client` (vs. the old blanket 400).
- `OAuth2ControllerTest` — three new cases: public client without PKCE → 400,
  user-tenant ≠ client-tenant → 400, confidential client missing secret → 401.
- `RefreshTokenServiceTest` — new test class asserting `createRefreshToken`
  never calls `revokeAllUserTokens` (BE-M5 invariant).

### Verified
- `mvn -DskipTests clean compile` — BUILD SUCCESS (459 sources).
- `mvn test -Dtest='OAuth2ControllerTest,OAuth2ServiceTest,RefreshTokenServiceTest'`
  — 39 tests, 0 failures. `OAuth2ServiceTest` write-side assertions migrated
  from pipe-match to JSON-field-match; read-side legacy pipe tests still pass
  via the fallback.
- `python3 -c "import yaml; yaml.safe_load(open('dynamic.yml'))"` — YAML OK.

## [2026-04-18c] — OIDC ui_locales pass-through on hosted-login authorize

### Added
- **`OAuth2Controller.authorize` accepts `ui_locales`** — OIDC Core §3.1.2.1
  optional parameter is now parsed on `GET /oauth2/authorize` and, when
  `display=page`, forwarded via `buildHostedLoginUri` as a query param on the
  `302 Location` pointing at `verify.fivucsas.com/login`. Tenants calling
  `FivucsasAuth.loginRedirect({ locale: 'tr' })` now land on a Turkish hosted
  login page instead of the browser-auto-detected default. Space-separated
  BCP47 tag lists are passed through unmodified; the hosted page honours the
  first supported tag (currently `tr`, `en`).
- **`OAuth2ControllerTest.authorize_WhenDisplayPageWithUiLocales_ShouldForwardLocale`**
  — MockMvc assertion that `Location` header contains `ui_locales=tr` when the
  authorize request supplies it alongside `display=page`.

### Tests
- `mvn test`: 839 / 839 passing (was 838; +1 new locale-forwarding assertion).
  27 skips remain (integration tests gated on `RUN_INTEGRATION=true`).

## [2026-04-18b] — Test-source drift repair (38 red → 0; 838/838 pass)

### Fixed
Ubuntu-latest CI surfaced 38 failing tests today that the broken self-hosted
runner had been silently skipping for weeks. Root cause: tests lagged behind
25+ legit source changes (constructor growth, RFC-8176 `amr` claim, Redis+DB
TOTP durability, NFC repository lookup, hosted-login controller bulk-up).
No real product bugs uncovered; no tests weakened, no `@Disabled` shortcuts.

Test files realigned:
- `controller/AuthControllerTest` — `UserRepository` JPA→domain-port import;
  +13 `@MockBean`s for the controller's grown 25-dependency constructor
  (`EnrollmentHealthService`, `NfcCardRepositoryPort`, `QrCodeService`,
  `WebAuthnCredentialRepositoryPort`, `AuditLogPort`, `AuthFlowRepositoryPort`,
  `TotpService`, `BiometricServicePort`, `WebAuthnService`,
  `MfaSessionRepository`, `TokenGenerationPort`, `RefreshTokenService`,
  `UserEnrollmentRepository`). Corrected register status 201, logout 204.
- `controller/EnrollmentControllerTest` — `+@MockBean EnrollmentHealthService`.
- `controller/OtpControllerTest` — `UserRepository` JPA→domain-port import.
- `controller/TotpControllerTest` — same import fix; stubbed new DB-persist
  path in `shouldVerifySetup`.
- `controller/UserEnrollmentFlowControllerTest` — rewrote `VerifyLiveness`
  test to match current local frame validation (controller no longer calls
  `biometricService.verifyLivenessPuzzle`).
- `application/service/AuthenticateUserServiceTest` — +4 mocks; switched
  stubs to 2-arg `generateAccessToken(email, amr)` form (RFC 8176).
- `application/service/GetCurrentUserServiceTest` — `+TenantRepository` mock.
- `application/service/ManageEnrollmentServiceTest` — +`NfcCardRepositoryPort`
  + `WebAuthnCredentialRepositoryPort` mocks; re-enroll test switched to
  PASSWORD (TOTP is not in `AUTO_COMPLETE_TYPES`).
- `application/service/handler/NfcDocumentAuthHandlerTest` —
  `+NfcCardRepositoryPort` mock; assertions aligned with real source strings
  (old "not yet available" / "NFC hardware" stubs replaced).
- `application/service/handler/TotpAuthHandlerTest` — `+UserRepository` mock
  for new Redis-miss→DB fallback in `resolveTotpSecret`.

Result: `mvn test` → `Tests run: 838, Failures: 0, Errors: 0, Skipped: 27`
(27 skips are Testcontainers integration tests gated on `RUN_INTEGRATION=true`).

## [2026-04-18] — V37 index reaffirmation + V38 SPA public client fix + CI split

### Changed
- **CI workflow (`.github/workflows/ci.yml`)** — split into two jobs:
  1. `test` (unit) on `runs-on: ubuntu-latest` runs `mvn -B -ntp test` against
     pure unit tests — no Docker, no Testcontainers. Fast, reliable on
     GitHub-hosted runners.
  2. `integration-tests` on `runs-on: [self-hosted, linux, x64]`
     (`hetzner-cx43`) runs `mvn -B -ntp -Dtest='*IntegrationTest' verify` with
     `RUN_INTEGRATION=true` so Testcontainers can reach the real Docker
     daemon. Depends on `test` via `needs: test` (sequential).
  - Rationale: `UserApiIntegrationTest`, `AuthenticationFlowIntegrationTest`,
    and `OAuth2PublicEndpointsSecurityIntegrationTest` are flaky on
    `ubuntu-latest` because Testcontainers cannot always reach the Docker
    daemon on GitHub-hosted runners. Gating via
    `@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")`
    makes them opt-in; the self-hosted runner (which has Docker locally
    installed) sets the env and runs them.
- **Integration test classes** — added
  `@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")`
  (import `org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable`) on
  the three `@Testcontainers` classes under `src/test/java/.../integration/`.
  When `RUN_INTEGRATION` is unset or not `"true"` (as on `ubuntu-latest`),
  JUnit Jupiter skips the entire class — no container startup attempt, no
  flake. Pure unit tests (e.g. `OAuth2ClientTest` under `entity/`) are
  unaffected and continue to run on both runners.
- **Maven parallelism** — `mvn -B -ntp -T 2C test` (2 threads per CPU core)
  on the unit-test job. Roughly halves wall-clock on the ubuntu-latest
  runner for a 633-test suite without affecting correctness since Surefire
  per-module parallelism is safe for our pure unit tests. Phase E3 from the
  2026-04-18 roadmap.

### Added
- **Flyway V37** (`V37__oauth2_clients_tenant_id_index.sql`) — idempotent
  `CREATE INDEX IF NOT EXISTS idx_oauth2_clients_tenant_id ON oauth2_clients(tenant_id)`.
  Addresses the sequential-scan finding from the 2026-04-16 five-agent audit on
  the `/api/v1/oauth2/authorize` hot path, where `client_id -> tenant_id`
  resolution was the critical lookup.
- Note: V24 already declares the same index; V37 is a safety net for
  environments where the V24 build never succeeded or was dropped manually.
  Running V37 on a healthy DB is a no-op (no table lock, no rewrite).
- **Flyway V38** (`V38__oauth2_web_dashboard_public.sql`) — flips
  `fivucsas-web-dashboard` to `confidential = false`. The web dashboard is a
  React SPA at `app.fivucsas.com` running in browser context and therefore
  cannot hold a client secret (RFC 6749 §2.1, RFC 8252 §8.4). V24 seeded it as
  `confidential = true` with a bcrypt-hashed secret; `OAuth2Service.exchangeCode`
  already accepts PKCE S256 in lieu of secret on the token endpoint so
  end-to-end auth continued to work, but the flag was incorrect. PKCE S256 is
  already mandatory for this client — no new verifier enforcement needed, only
  the metadata flag is being corrected. No code or entity changes required
  (`confidential` already exists on `OAuth2Client.java` from V34).

## [2026-04-16c] — Filtered public Swagger UI

### Added
- **Swagger UI at `/swagger-ui.html`** — public developer docs exposed
  unconditionally so third-party integrators (tenants using the hosted-login
  or OAuth2 flows) can explore the API. Matches the GitHub/Twilio/Stripe
  pattern where documentation is a first-class public surface.

### Changed
- **`SecurityConfig.java`** — swagger/openapi paths changed from
  `exposeDocs && !isProductionProfile()` gate to unconditional `.permitAll()`.
  H2 console stays gated (never public).
- **`application-prod.yml`** — enabled `springdoc.api-docs` + `swagger-ui`
  in prod profile (previously `enabled: false`). Added `paths-to-exclude` to
  hide admin surfaces:
  - `/api/v1/admin/**`, `/api/v1/tenants/**`, `/api/v1/users/**`,
    `/api/v1/roles/**`, `/api/v1/audit-logs/**`,
    `/api/v1/oauth2/clients/**`, `/actuator/**`
- **`SecurityHeadersConfig.java`** — emit a dedicated CSP for swagger paths
  (`default-src 'self'` + inline styles/scripts + `data:` fonts) so the UI
  renders. Non-swagger responses keep `default-src 'none'; frame-ancestors 'none'`.

### Security notes
- Only public developer endpoints visible: `/api/v1/auth/**`, `/api/v1/oauth2/**`
  (flows, not admin), `/.well-known/**`, `/api/v1/verification/**`,
  `/api/v1/biometric/**`, `/api/v1/nfc/**`, `/api/v1/otp/**`, `/api/v1/qr/**`,
  `/api/v1/step-up/**`, `/api/v1/webauthn/**`, `/api/v1/devices/**`,
  `/api/v1/enrollments/**`, `/api/v1/auth-methods/**`, `/api/v1/me`.
- 114 paths exposed, 0 admin endpoints leaked (verified via
  `curl https://api.fivucsas.com/api-docs | jq '.paths | keys'`).
- Authentication enforcement is unchanged — Swagger only documents the
  contract; it does not bypass per-endpoint auth/rbac.

## [2026-04-16b] — GDPR Art. 17 + Art. 20 compliance (data export + soft-delete purge)

Closes the P0 compliance gap flagged in the 2026-04-16 audit. No Flyway migration
required — the `users.deleted_at` column already exists from V2; this change only
maps it onto the `User` entity and adds the job + endpoints that consume it.

### Added
- **`GET /api/v1/users/{id}/export`** — GDPR Art. 20 portability. Returns a JSON
  bundle (`Content-Disposition: attachment`) containing user profile, enrollments,
  auth-flows, user-scoped audit logs (capped at 10 000 entries),
  verification sessions, OAuth2 clients (tenant admins only), and biometric
  enrollment metadata. **Excludes** password hashes, MFA secrets, session tokens,
  and raw biometric embeddings — embeddings live in the separate `biometric_db`
  and are never returned to clients (matches Auth0 / Okta precedent).
  (`UserDataExportController.java`, `UserDataExportService.java`,
  `UserDataExportUseCase.java`)
- **Rate limit** on data export — 1 request per hour per user via
  `RateLimitService.allowDataExport(userId)`, returns `429` with `Retry-After`
  header (RFC 6585). Checked **before** authorization to avoid ID enumeration
  via 403-vs-429 timing.
- **`USER_DATA_EXPORTED` audit event** emitted on every successful export with
  caller ID, IP, and target user ID.
- **`SoftDeletePurgeJob`** — GDPR Art. 17 / KVKK right-to-erasure. Daily
  `@Scheduled(cron = "0 30 3 * * *")` permanently purges users with
  `deleted_at < NOW() - 30 days`. Batched (100/tx) with
  `REQUIRES_NEW` propagation so a single bad row doesn't poison the run.
  Emits `USER_HARD_PURGED` per deletion. `audit_logs.user_id` is set to `NULL`
  via the V5 FK (history survives purge for SOC2 / ISO 27001 / KVKK 7-year
  retention).
- **Feature flag** `app.purge.softDelete.enabled` (default **false**). Flip per
  environment only after validating via dry-run.
- **`DELETE /api/v1/admin/purge/dry-run`** — super-admin endpoint returning
  cutoff timestamp, candidate count, and candidate IDs without mutating rows.
  Works regardless of the feature flag. Guarded by `@rbac.isSuperAdmin()`.
  (`PurgeAdminController.java`)
- **`RbacAuthorizationService.isSuperAdmin()`** — named alias for `isRoot()` so
  `@PreAuthorize` expressions read correctly at call sites.
- **`User.softDelete()` + `User.isSoftDeleted()`** — explicit soft-delete
  behavior on the entity; sets `deletedAt`, flips `status` to `INACTIVE`,
  clears `isActive`.
- **`UserRepository.findPurgeCandidates(cutoff, pageable)`** — JPQL query
  scoped to `deletedAt IS NOT NULL AND deletedAt < :cutoff`.
- **14 unit tests** covering export (self-access, tenant-admin delegation,
  cross-user denial, not-found, sensitive-field exclusion, unauthenticated,
  rate-limit) and purge (feature flag off/on, short-batch termination,
  audit emission, dry-run without mutation).

### Safety notes (operators)
- Purge job is **off by default**. Run dry-run in each environment and verify
  `candidateCount` / `candidateIds` match expectations **before** setting
  `APP_PURGE_SOFT_DELETE_ENABLED=true`.
- Purge is irreversible. The 30-day window starts from `deleted_at`, not from
  account creation.
- Audit-log history persists per regulatory retention — do not rely on purge
  to remove user references from audit trails.

## [2026-04-16] — PR-1 Hosted-first V1 + PR-1 review blockers

### Added
- **OAuth2 hosted-login** — `OAuth2Controller.authorize` `display=page` branch → 302 to `verify.fivucsas.com/login`; `POST /oauth2/authorize/complete` mints authorization code after MFA; `GET /oauth2/clients/{clientId}/public` returns branding metadata (OAuth2Controller.java +209 lines)
- **B1 permitAll** — `/oauth2/authorize/complete` + `/oauth2/clients/*/public` added to SecurityConfig permitAll chain; new `OAuth2PublicEndpointsSecurityIntegrationTest` hits the real SecurityFilterChain (NOT `addFilters=false`) to catch the anonymous-auth regression unit tests missed (SecurityConfig.java)
- **V34** Flyway migration — `oauth2_clients.confidential` boolean column for public-vs-confidential client distinction
- **V35** Flyway migration — `mfa_sessions.consumed_at` TIMESTAMP + `MfaSession.consume()` method for atomic code-mint replay guard (B4)
- **V36** Flyway migration — `mfa_sessions.client_id` column; enforced at `/authorize/complete` to block cross-client code replay within the same tenant (B2)
- **RFC 8252 loopback** — `OAuth2Client.matchesLoopbackRegistration()`: IPv4 `127.0.0.1` only (no `localhost`, no IPv6 `::1`), rejects any incoming query string, fragment tolerated (B5)
- **PKCE S256 enforcement** — `/authorize/complete` mandates `codeChallenge` + `codeChallengeMethod=S256` when `OAuth2Client.confidential == false`; rejects `plain` (B3)
- **Jackson redirect URI parsing** — `OAuth2Client.splitRegisteredRedirectUris()` uses `ObjectMapper.readValue(json, new TypeReference<List<String>>(){})` with malformed-JSON single-URI fallback; URIs with commas no longer corrupt allowlist (B6)
- **OAuth2ControllerTest** — 199 LOC covering new endpoints
- **OAuth2ClientTest** — 169 LOC covering exact-match + loopback-match including anyIncomingQueryIsRejected, fragmentIsTolerated, ipv6LoopbackRejected, variousPortsAccepted (13 tests)

### Fixed
- **Atomic code-mint** — `/authorize/complete` wraps code-mint + session-consume in `@Transactional`; `consumed_at` set BEFORE mint so retries fail fast (B4)
- **Tenant-mismatch status code** — `/oauth2/authorize/complete` returns 400 `invalid_request` instead of 403 per RFC 6749 §5.2 (no policy leak to unauthenticated callers)
- **Rate-limit `Retry-After`** — `/authorize/complete` and `/auth/login` 429 responses include `Retry-After` header so well-behaved clients back off (RateLimitInterceptor.java)
- **completedMethods derivation** — `AuthenticateUserService` derives from `MfaSession.getCompletedMethods()` instead of hardcoded `[PASSWORD]`; supports tenants whose first step isn't password
- **Cross-client replay** — MFA session bound to originating `client_id` at creation; `/authorize/complete` rejects session if `clientId` mismatches (B2)

### Changed
- **OAuth2Controller.authorize** — dropped redundant `isHtmlAccept` branch now that SDK always sets `display=page` explicitly

### Commits (preserved via merge-commit strategy on PR #16)
- `86ed1bf` permitAll hosted-login OAuth2 endpoints (B1)
- `ad293ce` Jackson redirect_uris parser (B6)
- `76d3b8c` PKCE S256 mandated for public clients (B3)
- `d840b8e` atomic MFA session consumption V35 (B4)
- `1f7993b` / `ae1bb7f` loopback hardening (B5 + IPv4/query tightening)
- `9d97e40` client_id bound to MfaSession V36 (B2)
- `5c9ed62` 403 → 400 on tenant mismatch
- `5daff87` drop isHtmlAccept branch
- `db5da7f` Retry-After on 429
- `aea7a9a` derive completedMethods from MfaSession
- Merged to main in `8059ca9` (fast-forward)

## [2026-04-15]

### Added
- **Rate limit** on `/auth/mfa/qr-generate` — defends against broken clients looping on QR generation. Uses biometric bucket (20/min per IP). Sends `Retry-After` header so the widget can surface a friendly countdown instead of re-firing. (RateLimitInterceptor.java)

## [2026-03-07] — Initial audit and documentation

### Added
- CLAUDE.md with project context, known issues, and auth handler status
- ROADMAP.md with phased integration plan
- AUTH method integration gap analysis in TODO.md (8 new items: AUTH-1 through AUTH-8)

### Documented
- Auth handler status matrix: 7/10 methods working, 3 broken at runtime
- NfcDocumentAuthHandler always returns failure (hardcoded stub)
- FingerprintAuthHandler/VoiceAuthHandler fail due to biometric-processor stubs
- WebAuthnController registration endpoints ready but no frontend enrollment UI
- TotpController/QrCodeController not connected to frontend components
- BiometricServicePort cross-service integration gaps

### Previous
- Cross-module integration audit (March 2026): 41 issues identified
- Previous audit (Feb 2026): 74/100 readiness score, 3 critical issues

## [2026-04-15b] — MFA reuse check fix

### Fixed
- **TOTP + EMAIL_OTP collision**: reuse check compared AMR values, but both TOTP and EMAIL_OTP map to RFC 8176 `"otp"`. After TOTP completed, subsequent EMAIL_OTP returned 400 "METHOD_ALREADY_USED". Now reuse is tracked by `AuthMethodType.name()` (e.g. "TOTP", "EMAIL_OTP") and AMR values are mapped at JWT issuance. (AuthController.java, AuthenticateUserService.java)
