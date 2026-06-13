# CLAUDE.md - Identity Core API

## Project Overview

Java 21 / Spring Boot 3.4.7 backend API for FIVUCSAS biometric identity platform.
Hexagonal Architecture with Ports and Adapters. Production URL: https://api.fivucsas.com

## Current state (2026-06-07)

Three PRs merged to `main` on this date (HEAD ~`3aafc69`):
- **#209** — untrack the stale `.env.hetzner` + harden `.gitignore`.
- **#210** — WebAuthn test reconciliation (`completeEnrollment` → `autoBindEnrollment`),
  `NfcSerial` `Locale.ROOT` casing, OAuth2 token-mint routed off `entity.User` via the
  `OAuth2TokenMintPort`/Adapter (ArchUnit boundary).
- **#211** — authorization IDOR / PII-leak / abuse-throttle hardening (NFC enroll/remove,
  user-settings + enrollment cross-tenant guards, push-token bind, NFC PII gate, locale
  casing, OTP-send throttle).

Key facts after the merge:
- **Unit suite is GREEN: `mvn -o test` → 1670 run / 0 fail / 0 error / 67 skip.** (Run on
  JDK 21 — the default `java` on PATH is JDK 8 and will fail. The 67 skipped are
  Testcontainers/DB integration tests, not runnable with Docker off.)
- **Integration lane RESTORED — GREEN (2026-06-12, PR #221).** `Integration tests
  (Testcontainers)` now passes **94 run / 0 fail / 0 error / 0 skip**, so BOTH required
  checks on `main` (`Maven test (unit)` + `Integration tests (Testcontainers)`) are green
  and **`--admin` is no longer needed for api merges.** The red was NOT environmental —
  it was test-only staleness + a latent CI-guard bug. Fixes
  (all test/CI-only, NO production change): (1) #220 Instant→Timestamp fixture; (2) stale
  `CrossTenantIsolationIT.superAdminNoHeader_crossTenant` ×6 — they predate PR #134's
  `@Filter(tenantFilter)` rollout, so a header-less ROOT now scopes to HOME (NOT a leak),
  test updated + true cross-tenant proven via explicit `TenantFilterBypass`; (3) register
  ITs got `EmailDomainNotAllowed` → `app.default-tenant-slug` points at a test-only
  `default` catch-all tenant (`db/test-fixtures/V86_5__…`, single-step PASSWORD flow);
  (4) 429 cascade → reset per-IP rate-limit buckets `@BeforeEach`; (5) register expects
  201 (not 200), logout is authenticated + 204 (not anon 200); (6) the CI guard now sums
  JUnit `@Nested` surefire shards. **Do NOT use the `system` tenant as the IT catch-all**
  — V29 gives it a 2-step PASSWORD+EMAIL_OTP flow, so login returns an MFA challenge.
- **ArchUnit `entity.User` boundary baseline was refrozen** during the #211 merge
  (18 stale lines removed, 0 grandfathered) — a legitimate refreeze of a line-number
  baseline that had drifted against `main`, not a suppression of new violations.
- **`.env.hetzner` is now untracked + gitignored.** The leaked blob (`f9f0f2d`) holds
  STALE GCP-era creds (verified by SHA-256 fingerprint), NOT live secrets — live secrets
  are in the never-committed `.env.prod`. Emergency rotation was NOT required (verified);
  the 2026-06-06 rotation procedure stands for any future *live* leak. The history-purge
  of the dead blobs is tracked as an owner decision in FIVUCSAS#197.

See `CHANGELOG.md` 2026-06-07 for the authz-IDOR / test / security details.

## Current test state (2026-06-07)

`mvn -o test` (JDK 21 — the default `java` on PATH is JDK 8 and will fail) is **GREEN:
1670 run, 0 failures, 0 errors, 67 skipped** (post-#211; the #210 session reported 1648
before #211's tests landed). The 67 skipped are Testcontainers/DB
integration tests (`*IntegrationTest`, `*MigrationTest`, `TenantRlsRegressionTest`,
`SoftDeletePurgeJobConcurrencyTest`, DB-gated `AuthControllerTest` cases) — **not
runnable without Docker**; verify them in CI (self-hosted runner), not on a Docker-off
box. ArchUnit boundary tests run as ordinary unit tests (no DB) and are green.
- **Locale**: this build/runtime defaults to `tr_TR`. Any `toUpperCase`/`toLowerCase`
  MUST pass `Locale.ROOT` (`i → İ` corruption). `domain.model.NfcSerial` is now compliant.
- **Known fixed (2026-06-07)**: the 3 WebAuthn test failures from the
  `completeEnrollment` → `autoBindEnrollment` rename are resolved (test updated to the
  current production API; production unchanged). See `CHANGELOG.md` 2026-06-07.
- **Security note**: the git-tracked `.env.hetzner` leak (`f9f0f2d` on `origin/main`)
  holds STALE GCP-era creds (verified by SHA-256 fingerprint), NOT live secrets — live
  secrets are in the never-committed `.env.prod`. Emergency rotation was NOT required;
  the 2026-06-06 rotation runbook stands as the procedure for any future *live* leak.
  Hygiene (untrack + gitignore) on branch `claude/untrack-env-hetzner-secret`.

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

- **Biometric enrollment-probe (login triage F2/F7/F9, 2026-06-12)**: `EnrollmentHealthService.hasBiometricData(FACE/VOICE)` no longer FAKES enrollment as always-present when the bio service is merely reachable (the old behaviour routed un-enrolled users into a VOICE step that could never pass → "No voice enrollment found" → generic "Doğrulama başarısız"; FACE was masked because most users did enroll). It now asks the biometric-processor whether a template REALLY exists via `BiometricServicePort.{voiceEnrollmentExists(userId), faceEnrollmentExists(userId, tenantId)}` → bio `GET /voice|/face/{userId}/exists`. **Tri-state**: definitive `TRUE`→enrolled; definitive `FALSE`→not-enrolled (the stale row is auto-revoked by `validateEnrollments`, so it stops being offered/auto-picked); `null` (UNKNOWN = bio OUTAGE: transport/5xx)→**fail-OPEN** (return true) so an outage never locks everyone out. Face probe is tenant-scoped (resolved via `userJpaRepository.findTenantIdById`) for verify-path parity. **KILL-SWITCH**: `app.auth.enrollment-probe.enabled` (`APP_AUTH_ENROLLMENT_PROBE_ENABLED`, default `true` = the fix). Set `false` to instantly revert to the legacy "trust the enrollment row if the bio service is reachable" behaviour with NO redeploy. **Prod rollout = deploy bio FIRST (the existence endpoints), then identity.**
- **N-step MFA**: JWT deferred until all steps complete. `POST /auth/mfa/step` with session token. RFC 8176 `amr` claim.
- **WebAuthn base64**: `decodeBase64()` normalizes standard→URL-safe. NEVER use `Base64.getUrlDecoder()` on frontend data.
- **Session path handlers**: Accept BOTH old and new field names for backward compatibility (B1-B6).
- **Entity state**: Professional pattern — NfcCard/OAuth2Client use `revokedAt` timestamps, User `isActive` synced from status enum via `@PrePersist/@PreUpdate`.
- **NFC enrollment**: Auto-creates user_enrollments record. Reactivates existing inactive card on re-enrollment.
- **NFC serial — CANONICAL FORMAT (WS2, 2026-05-30)**: web sends the serial as
  lowercase-with-colons (`04:a2:24:5b:6f:71:80`), mobile sends UPPERHEX
  (`04A2245B6F7180`). The API normalizes EVERY inbound serial at the ingest
  boundary to **upper-case hex, NO separators** via `domain.model.NfcSerial.canonicalize`
  (strip `: - . space`, upper-case, keep stripped value iff pure hex; non-hex/opaque
  serials are upper-cased + trimmed only, separators preserved). Stored + looked-up
  value is always canonical, so a mobile-enrolled card matches a web verify and
  vice-versa. Applied in `ManageNfcCardService.{enrollCard,verifyCard,searchByCardSerial}`,
  `NfcDocumentAuthHandler.validate`, AND `NfcDocumentVerifyMfaStepHandler.verify`
  (the latter was MISSING canonicalize on its opt-in branch → web taps failed even
  when serial-only was enabled; fixed 2026-06-01).
- **NFC serial-only login ENABLED in prod (2026-06-01)**: the live login path is
  `POST /auth/mfa/step` → `VerifyMfaStepService` → `NfcDocumentVerifyMfaStepHandler`,
  which was **fail-closed by default** (`fivucsas.nfc.serial-only-auth-enabled=false`)
  — so an enrolled student card always failed as "Verification failed for NFC_DOCUMENT"
  (audit reason `nfc_card_not_found_or_not_owned`, even though the lookup never ran).
  Set `FIVUCSAS_NFC_SERIAL_ONLY_AUTH_ENABLED=true` in `.env.prod` (accepted documented
  risk: campus/student cards are plain MIFARE UID-only, no ICAO chip → chip passive-auth
  can never apply to them; NFC is one factor inside MFA, never sole). Kill-switch: unset
  the var + `up -d` to revert to fail-closed (no rebuild). NOTE the legacy
  `NfcDocumentAuthHandler` (AuthMethodHandler path) was never fail-closed — the two
  NFC handlers disagreed; the modern `/auth/mfa/step` handler is the live one.
- **NFC chip passive-authentication (WS2 trust gate, 2026-05-30)**: serial-only
  proves "this serial is enrolled" but NOT that the physical chip is genuine. The
  `biometric-processor` validates the eMRTD `EF.SOD → Document Signer → CSCA` chain
  + DG-hash binding (CPU-only, X-API-Key). The api treats the verdict as
  AUTHORITATIVE and is **FAIL-CLOSED** (error / `NO_TRUST_STORE` / non-authentic ⇒
  reject). Wired via `BiometricServicePort.verifyNfcChipAuthenticity(sodB64, dataGroups)`
  → `BiometricServiceAdapter` → bio `POST /api/v1/nfc/verify-authenticity`
  (frozen contract, bio PR #131: request `{sod_b64, data_groups:{"1":..,"2":..}}`;
  response `{is_authentic, reason, reason_code, ds_subject, ds_serial, csca_matched,
  dg_hash_results, sod_hash_algorithm}`). Single verdict interpreter:
  `application.service.nfc.NfcChipAuthenticityVerdict` (only place that reads
  `is_authentic`). Endpoints/paths that gate on it:
    - `POST /api/v1/nfc/verify-authenticity` — standalone trust check (200 authentic;
      422 `NFC_PA_NOT_AUTHENTIC` fail-closed; 400 `NFC_PA_MISSING_SOD`).
    - `POST /api/v1/nfc/enroll` — when the payload carries `sod`/`sod_b64`, enrollment
      is gated (422 if inauthentic; serial-only enroll unchanged).
    - `NfcDocumentAuthHandler` MFA step — when step data carries SOD/DGs, the step
      fails closed if the chip isn't authentic before the serial lookup.
  Accepts `sod` or `sod_b64`, and DG keys as `dg1..dgN` or bare `1..N`.
  **Operator**: CSCA roots must be dropped into the bio container's
  `NFC_CSCA_TRUST_DIR` (default `app/core/csca_trust_store/`) — until then every
  verify returns `is_authentic=false, reason_code=NO_TRUST_STORE`, so any client
  that SENDS a SOD will be rejected (serial-only flows are unaffected).
- **CORS**: api.fivucsas.com, app.fivucsas.com, demo.fivucsas.com, verify.fivucsas.com

## Flyway Migrations (V1-V83)

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
V69: Role/user_type unification — rename the global SUPER_ADMIN role → ROOT
     (UUID + grants unchanged) + elevate-only user_type tier backfill (ROOT-role
     holders → user_type ROOT; TENANT_ADMIN-role holders → ≥TENANT_ADMIN; never
     demotes). user_type is the SOLE platform-tier authority; role = within-tenant
     RBAC. See docs/IDENTITY_ROLE_UNIFICATION.md.
V70: users.identity_id SET NOT NULL — preceded by a BEFORE-INSERT trigger
     `ensure_user_identity` that auto-assigns an identity (reuse-by-email or
     create) on any user insert lacking one, so all creation paths + direct SQL +
     future callers stay covered (mirrors the V53 trigger pattern). Self-gating
     (RAISE EXCEPTION if any NULL remains before the ALTER).
V71: ROOT role granted all 48 permissions — backfills the full permission set onto
     the renamed ROOT role (post-V69) so the platform-owner tier holds every
     permission grant. Idempotent (INSERT … ON CONFLICT DO NOTHING on
     role_permissions). See docs/IDENTITY_ROLE_UNIFICATION.md.
V72: WebAuthn discoverable-passkey columns (2026-05-30, PR #161) —
     webauthn_credentials.discoverable BOOLEAN + user_handle (the stable per-user
     handle returned in a usernameless `navigator.credentials.get()`). Additive,
     nullable/defaulted. Backs the anonymous passkey login endpoints below.
     **V72 applied in prod (2026-05-30 rebuild).**
V73: config-driven login engine — adds AuthMethodType PASSKEY + APPROVE_LOGIN,
     seeds their auth_methods rows, adds auth_methods.supports_usernameless
     (TRUE for PASSKEY/APPROVE_LOGIN/QR_CODE), and widens chk_auth_method_type
     (preserving the full V28 list). PASSKEY = discoverable mode of WebAuthn;
     APPROVE_LOGIN = number-matching mode of the QR cross-device method.
     V73 is ADDITIVE/reversible — safe to leave applied if the image rolls back.
V74: APPROVE_LOGIN supports_usernameless → false (identifier-first correction).
V75: activate the VOICE login auth method — V16 seeded the VOICE row with
     is_active=false, so GET /api/v1/auth-methods filtered it out and the
     dashboard auth-flow builder never offered it. Single guarded idempotent
     UPDATE, no schema change. **GESTURE_LIVENESS is deliberately NOT a login
     auth method** — it is an active-liveness anti-spoofing sub-component of FACE
     (no auth handler), so it must NOT be seeded as a selectable auth_methods row.
     Applies on the next api rebuild.
V76: scope tenant-scoped TENANT_ADMIN roles to TENANT-level permissions only —
     strip the 7 PLATFORM grants (tenant.create/delete, system.audit/configure,
     permission.create/update/delete) from every `TENANT_ADMIN` role with a
     non-NULL tenant_id. The fivucsas TENANT_ADMIN held all 48 (identical to
     ROOT) — over-privileged + misleading in the Roles UI. ROOT (tenant_id NULL)
     keeps all 48 (its real power is user_type=ROOT, which bypasses perm checks).
     Idempotent DELETE; no runtime re-seed (DataInitializer doesn't touch
     role_permissions). Applies on the next api rebuild.

**V34-V83 applied in prod (max applied = V83, verified 2026-06-04). The 2026-05-30 rebuild added V72 (discoverable-passkey columns); the 2026-05-31 rebuild added V73-V76; the 2026-06-02/03 rebuilds added V77-V82 (incl. V80 fivucsas-mobile OAuth client, V81 consent singleton, V82 cross_tenant clients); the 2026-06-04 rebuild added V83 — widen `chk_enrollment_method` to include APPROVE_LOGIN + PASSKEY (V73 added the enum but missed this constraint, so APPROVE_LOGIN auto-enrollment silently failed). Same rebuild shipped cross-device QR + APPROVE_LOGIN MFA factors + NFC cross-membership resolution (dark, flag `app.identity.cross-membership-enrollment-resolution`).**

### Identifier-first preflight now returns the resolved login-config (2026-05-31)

`POST /auth/login/preflight` previously returned `{eligible:true}`; it now returns
`LoginPreflightResponse {eligible, loginConfig}` where `loginConfig` is the caller's
RESOLVED tenant login-config (`AuthenticateUserUseCase.resolveHomeTenantId(email)` →
`LoginConfigService.getLoginConfigForTenantOrPlatform(tenantId)`). This lets the
cross-tenant **dashboard** (app.fivucsas.com — no tenantId/clientId of its own) show
the caller's REAL flow (Layer-1 methods + step count → "1/3") at the email step
instead of the hardcoded platform PASSWORD-first/totalSteps=1. Enumeration-safe:
unknown email → null tenant → platform default (indistinguishable from a single-step
password tenant). Backward compatible (the old `eligible` field is unchanged).
NOTE: `POST /auth/login/begin` (the identifier-first `beginIdentifierLogin()` path)
IS wired and live (corrected 2026-06-03 — the prior "DEAD / no such endpoint / 401"
note was stale; an empty body now returns 400, and a real identifier-first begin for
a `@marun.edu.tr` account was observed in prod logs). The dashboard still presents
password-first by choice (the fivucsas flow is "Password + any 2FA + any 3FA"); true
arbitrary first-factor (e.g. start with FACE when password is only a Layer-1 CHOICE)
remains a future UI feature on both surfaces.

### Config-driven login engine — kill-switch (task #16, ships DARK 2026-05-30)

The config-driven login engine (Layer-1-as-config + usernameless-into-flow) is
gated by `ConfigDrivenLoginPolicy` and ships **OFF**. When OFF, login is
byte-identical to the legacy password-first behavior. Flip WITHOUT a redeploy:
- `APP_AUTH_CONFIG_DRIVEN_LOGIN=true` — enable for ALL tenants (master switch).
- `APP_AUTH_CONFIG_DRIVEN_LOGIN_TENANTS=<uuid>,<uuid>` — canary specific tenants
  while the master switch stays false.
Roll out dark → staging soak → canary one tenant → global; **revert = unset the
env var** (no rebuild). `/api/v1/auth/login-config` also returns the legacy
password-first shape whenever the engine is OFF for the tenant, so the UI agrees
with the runtime path. The endpoint accepts EITHER `?tenantId=<uuid>` (dashboard /
widget) OR `?clientId=<oidc-client-id>` (the hosted verify.fivucsas.com surface,
which only carries the OIDC client_id → tenant resolved via `oauth2_clients`);
exactly one is required, and an unknown/tenant-less client_id returns 404.
The response also carries **`engineActive`** (PR #168) — `true` when the engine
is ON for the tenant (master switch or per-tenant canary). It is the single
signal the web login UI reads to switch on the **identifier-first** experience
(collect identity on screen 1, present password + every factor afterward);
`engineActive=false` keeps the legacy single-screen email+password form, so the
UI redesign reverts with the env flag and no web redeploy.

### Client-side embedding kill-switches — FACE + VOICE (default OFF)

Two independent gates route a precomputed client-computed embedding to the
biometric-processor's embedding endpoints instead of uploading the raw
image/audio (privacy + GPU-less; the raw media never leaves the device). Both
default OFF (legacy server-side path, byte-identical), flip WITHOUT a redeploy,
and support per-tenant canary. **Both MUST be passed via the compose
`environment:` block** (the service uses an explicit block, NOT `env_file:` — a
var only in `.env.prod` is silently dropped; this exact gap once broke the face
flag).

- **FACE** — `ClientSideEmbeddingPolicy` (`app.auth.client-side-embedding`):
  `FaceVerifyMfaStepHandler` + `BiometricController.enrollFaceEmbedding` route a
  512-d Facenet512 vector to bio `/verify-embedding` / `/enroll-embedding`.
  Env: `APP_AUTH_CLIENT_SIDE_EMBEDDING(_TENANTS)`.
- **VOICE (audit H3, GPU-less)** — `ClientSideVoiceEmbeddingPolicy`
  (`app.auth.client-side-voice-embedding`): `VoiceVerifyMfaStepHandler` (reads
  the `embedding` key off the MFA `data` map when ON, else the legacy `voiceData`)
  + `BiometricController.enrollVoiceEmbedding`
  (`POST /api/v1/biometric/voice/enroll-embedding/{userId}`,
  `VoiceEnrollEmbeddingRequest`, 256-length-validated, fail-closed when OFF) route
  a 256-d Resemblyzer speaker vector to bio `/voice/verify-embedding` /
  `/voice/enroll-embedding`. Env:
  `APP_AUTH_CLIENT_SIDE_VOICE_EMBEDDING(_TENANTS)`.

SECURITY: an embedding carries no media, so the bio side cannot run
liveness/replay on it — an embedding FACE/VOICE factor MUST be paired with a
liveness factor in the auth flow. **Rollout ordering:** flip this (identity) flag
ON BEFORE the web `VITE_CLIENT_SIDE_*_EMBEDDING` flag (web-ON + identity-OFF
breaks the factor). The VOICE web preprocessing port is still a documented
scaffold (browser mel+VAD not yet parity-validated — see biometric-processor
`docs/design/VOICE_CLIENT_EMBEDDING_SPEC.md`); keep the voice flag OFF until it is.

### Operator reality — 2026-05-30 stabilize-&-harden backlog (P1-1 + P1-5, DEPLOYED)

- **P1-1 — cross-tenant isolation ITs are now a CI gate (PR #155/#156).** The
  `integration-tests` job actually RUNS the isolation ITs
  (`-Dtest='*IntegrationTest,*IT'`), BLOCKS the pipeline (no `continue-on-error`),
  and asserts they executed. Three unit tests (TenantFilterBypass + rbacService
  mocks) were fixed to unblock `needs: test`. **Operator follow-up:** add
  `Integration tests (Testcontainers)` as a REQUIRED status check in
  `main`-branch protection so a red gate can't be merged around.
- **P1-5 — Flyway chain is DR-safe from a fresh DB (PR #157, DEPLOYED).** V29 was
  rewritten to resolve the Default-Login flow + EMAIL_OTP by NATURAL keys (it used
  prod-only hardcoded UUIDs, so a fresh DB diverged); the V40 pkey collision and the
  invalid `COMMENT 'a'||'b'` syntax in V40/V41 were fixed. The chain now applies
  **71/71 from an empty database**. Shipped to prod via a one-time `flyway repair`
  with `validate-on-migrate=true`. Runbook: `docs/RUNBOOK_FLYWAY_V29_REPAIR.md`.

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

## Operator reality (2026-05-30 update)

- **Cross-device / authenticator login SHIPPED + DEPLOYED (PR #161, V72; CI gate fixes #160).**
  - **Passkey hybrid login (discoverable + usernameless).** `register-options` now sets
    `residentKey=required` + `UV=required`. NEW **anonymous** endpoints (both `permitAll` in
    SecurityConfig): `POST /api/v1/webauthn/passkey/authenticate-options` (returns an assertion
    challenge with an EMPTY `allowCredentials`) and `POST /api/v1/webauthn/passkey/authenticate`
    (resolves the user by the asserted `userHandle`, then mints a session). Backed by V72
    (`webauthn_credentials.discoverable` + `user_handle`). This is the browser-native
    cross-device ("use your phone") path — no companion app required.
  - **No-Firebase, number-matching approve-login.** Redis-backed, modeled on `QrSessionService`:
    `POST /api/v1/auth/approve-login/session {email}` → `{sessionId, matchNumber, …}` (permitAll),
    GET poll, `GET /api/v1/auth/approve-login/pending` (authenticated approver lists pending
    requests), `POST /api/v1/auth/approve-login/{id}/decide {decision, matchNumber}` (mints tokens
    like the QR approve path). **`matchNumber` is a zero-padded STRING (e.g. "07")** — never type
    it as a number on a client (leading zeros drop). An unknown-email request returns a decoy
    session (no account-existence oracle). client-apps #53 is the shared approver KMP stack.
  - Prod: api rebuilt, V72 applied, `/webauthn/passkey/authenticate-options` +
    `/auth/approve-login/session` return 200; rollback tag
    `identity-core-api-identity-core-api:rollback-pre-passkeys-20260530`.
- **`User.identity` association → `insertable=false, updatable=false` (PR #160).** PROD-SAFE
  fix: `identity_id` is owned by the V70 BEFORE-INSERT trigger + the native `repointIdentity`
  UPDATE, so a routine entity UPDATE (e.g. `lastLoginAt`) whose in-memory `identity` is null
  right after a trigger-populated insert no longer flushes `identity_id=NULL` (V70 is NOT NULL).
  Nothing persists the association (account-linking = native query; seeds = raw JDBC), so it is
  safe. Pattern: never let a JPA association OWN a column a DB trigger/native query owns.
- **Integration-test gate — NOW GREEN (2026-06-12, PR #221); historical context below.**
  → See the **"Integration lane RESTORED"** bullet at the top of this file. The gate is
  green (94/0/0) and `--admin` is no longer needed. The history: the
  `Integration tests (Testcontainers)` gate is REQUIRED (P1-1, #155) but was NEVER green
  (deep pre-existing test-infra rot). The operator authorized a **ONE-TIME admin-merge
  exception** for the four orthogonal auth PRs (#159/#160/#161 + web #137), with manual
  cross-tenant staging smoke; the gate stays REQUIRED for everyone else. PR #160 began
  genuinely greening it (RSA ephemeral in the integration profile, IT NOT-NULL slug, dup
  tenant slug, JWT secret length, Redis service, `identity_id` seeding, `User.identity`
  entity fix + teardown soft-deletes); #220 fixed the Instant→Timestamp fixture; **#221
  finished it** (stale cross-tenant expectations, default-tenant catch-all, rate-limit
  isolation, 201/204 status fixes, `@Nested` surefire-guard fix). This Hetzner box
  cannot run Testcontainers ITs (no Docker socket for TC in the sandboxed shell) — verify
  ITs via CI.
- **Identity & account-linking Phases 1-5 ALL DEPLOYED + ROOT role/user_type
  unification SHIPPED (2026-05-30).** The five-phase Model-A identity layer is now
  fully live: Phase 1 person/identity layer (V65-V67), Phase 2 account linking
  (`/identity/link/initiate|confirm`, `/unlink`, `/identity/me`), Phase 3 biometric +
  per-tenant consent Model A (V68 `identity_tenant_biometric_consent`; the api
  orchestrates the canonical (identity,method) enrollment, the bio store is NOT
  re-keyed; default-DENY), Phase 4 OIDC pairwise `sub` (flag
  `app.identity.oidc-subject-identity`, **default OFF / dormant**), Phase 5 unified
  login + in-session membership switch (`POST /auth/switch-membership` token-exchange;
  see the detailed Phase-5 block below — note it is no longer "PR OPEN", it shipped).
  See `docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md`.
- **ROOT role/user_type unification (V69 + V71, `docs/IDENTITY_ROLE_UNIFICATION.md`).**
  `user_type` is the SOLE platform-tier authority (`ROOT` › `TENANT_ADMIN` ›
  `TENANT_MEMBER` › `GUEST`); `role` is purely within-tenant RBAC. The global
  `SUPER_ADMIN` role was RENAMED to `ROOT` everywhere (DB/backend/frontend); V69
  renames the role (UUID + grants unchanged) and elevate-only backfills `user_type`;
  V71 grants the renamed ROOT role all 48 permissions. `/auth/me` (`UserResponse`)
  now returns `userType` so the frontend trusts the real tier instead of inferring it
  from a role string. UI label for the top tier = **"Root"**.
- **Browser-sweep fixes (2026-05-30) — user-centric "/my" endpoints under a foreign
  X-Tenant-ID scope.** Several self-service "my" reads 500/404'd when a ROOT caller had
  a foreign tenant active, because the Hibernate `@Filter(tenantFilter)` scoped the
  caller's OWN row/membership lookups to the foreign tenant. Fixed by routing the
  self-resolution through `infrastructure.multitenancy.TenantFilterBypass` (clears
  `TenantContext` + disables `tenantFilter` for the lookup, restores after — identity is
  keyed by unique user, NOT a cross-tenant leak; the `@SQLRestriction` soft-delete guard
  is untouched). This is the same pattern documented for the tenant-switcher 403 fix —
  **apply `TenantFilterBypass` to any new user-centric `/my` read that must resolve the
  CALLER regardless of active tenant.** Concretely: auth-methods enrollment 500 (#151),
  `/auth/sessions/my` 404 (#153), `/guests` soft-deleted-proxy 500 (#152). Also:
  accept-invite with an existing email now returns **409** (was 500).

## Operator reality (2026-05-29 update)

- **Identity/account-linking Phase 5 (in-session membership switch) — PR OPEN, NOT
  merged/deployed.** `POST /api/v1/auth/switch-membership {targetUserId}` (authenticated):
  an authenticated person assumes another of THEIR OWN linked memberships without re-login
  (token exchange / account switch, NOT a privilege grant). Same-identity HARD GATE → 403
  (`MembershipSwitchForbiddenException`, the ONLY barrier between accounts); target must be
  ACTIVE (not locked/suspended/soft-deleted) + tenant ACTIVE → else 409
  (`MembershipNotSwitchableException`). Mints a NEW access+refresh pair AS the target via the
  EXISTING post-login mint path (`JwtService` + `RefreshTokenService.createRefreshToken`,
  bridged by `MembershipSwitchAdapter` — the only `entity.User` importer); carries the caller's
  `amr` + `auth_time` and stamps `act={"sub":<caller>}` + `switched_from=<caller>`. Refresh
  token is a normal target-membership token. Response = `/auth/login` `AuthResponse` shape.
  Audited `MEMBERSHIP_SWITCHED` (`logTenantManagementEvent`: actor = caller, resource/tenant =
  target tenant — never a tenant id in the user_id slot). Config flag
  `app.identity.require-stepup-on-switch` (`APP_IDENTITY_REQUIRE_STEPUP_ON_SWITCH`, default
  **false**) in application.yml + application-prod.yml — when true, requires a fresh caller
  password in the body before minting. NO Flyway migration. Tests: `SwitchMembershipServiceTest`
  + `MembershipSwitchControllerTest`; ArchUnit `UserDomainBoundaryTest` green (no new
  `entity.User` imports in application/controller). web TopBar switcher still to wire.
- **Identity/account-linking Phases 2/3/4 DEPLOYED (api #142/#143/#141, main `114b8eb`,
  prod image `474c8d12`; web #128/#127 on Hostinger; parent #95).**
  - **Phase 2 (account linking):** `POST /api/v1/identity/link/initiate` (OTP to target email
    via Redis — no new table), `/link/confirm` (OTP + caller password step-up → re-points
    `users.identity_id`), `/unlink` (fresh identity, reversible), `GET /identity/me` (person
    view: emails + memberships across tenants). Guardrails: no same-tenant link, both ACTIVE,
    audited `IDENTITY_LINKED`/`IDENTITY_UNLINKED`, rate-limited. web "Linked Accounts" Profile
    section. NOTE: login is still PER-ACCOUNT (per email→membership); linking is additive.
  - **Phase 3 (biometric + per-tenant consent, Model A):** `V68 identity_tenant_biometric_consent`
    (cross-tenant, NO `@Filter`). Bio pgvector store NOT re-keyed — the api orchestrates: a
    consented verify in tenant B routes to the person's CANONICAL (identity,method) enrollment;
    **default-DENY** (no consent → behaves exactly like not-enrolled). `GET/POST
    /api/v1/identity/biometric/consents` (membership-guarded, audited `BIOMETRIC_CONSENT_CHANGED`).
    web per-tenant consent toggle. `IdentityBiometricConsentIT` (RUN_INTEGRATION). bio unchanged.
  - **Phase 4 (OIDC `sub`):** `app.identity.oidc-subject-identity` flag **default OFF** (dormant —
    `subject_types_supported=public`, sub unchanged). ON ⇒ pairwise `base64url(SHA-256(sector|
    identityId|salt))` per RP. Dashboard access-token principal untouched. `PairwiseSubjectResolver`.
  - Validated on staging before prod (link/unlink, consent grant/403-guard/revoke, OIDC discovery
    public). Prod: V68 applied, consent table live, flag dormant.
- **Identity/account-linking Phase 1 DEPLOYED (PR #139, prod via image after `e74cfac`).**
  Approved Model-A design in `docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md` (#138). Phase 1 =
  person/identity layer, ZERO behavior change: `V65 identities`, `V66 identity_emails`
  (unique on `lower(email)`), `V67 users.identity_id` + PL/pgSQL email-grouped backfill
  (one identity per distinct email → links same-person cross-tenant rows). `Identity`/
  `IdentityEmail` entities carry **NO `@Filter`** — they are cross-tenant/platform-level BY
  DESIGN (don't "fix" this). Prod backfill: 31 users → 30 identities (the one cross-tenant
  duplicate email `glsm.2212@gmail.com` collapsed to 1 identity / 2 user rows), 0 NULL
  identity_id, login/admin unchanged. `users.identity_id` is nullable for now — a later
  migration sets NOT NULL once prod backfill is confirmed. Phases 2 (account linking),
  3 (biometric-on-identity + per-tenant consent, `V68`), 4 (OIDC `sub`, flag-gated) follow.
- **P1-3 enrollment score persistence DEPLOYED (PR #137, main `f6edc21`, prod image
  `0ab29095`; bio #123).** All `user_enrollments` had NULL quality/liveness because the web
  flow is enrollFace→createEnrollment→complete: `recordBiometricScores` no-op'd at
  enrollFace (no row yet) and `complete`'s `completeEnrollment(data,null,null)` then nulled
  scores. Fixes: `entity.UserEnrollment.completeEnrollment(data,q,l)` only sets non-null
  scores (preserves); `ManageEnrollmentService.recordBiometricScores` UPSERTS via
  `startEnrollment` + `TenantContext` when no row exists. Bio: real VOICE quality metric
  (duration+loudness+SNR, 0-100) replacing the `1.0` placeholder, shipped via the
  `Dockerfile.liveness-overlay` (boot-tested, restarts=0). Validated live on staging: a
  PENDING row with scores survived `createEnrollment` + the `complete` endpoint that
  previously nulled them. (Dataset-photo FACE e2e is blocked by the correctly-working
  anti-spoof liveness gate.)
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
  (RUN_INTEGRATION-gated → P1-1 makes it a CI gate).
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
- **RESOLVED (WS5, 2026-05-30):** guest invitations now send an email. The accept-link
  mail was wired in PR #119 (`EmailService.sendGuestInvitation` + `SmtpEmailService`
  SMTP impl, called from `GuestLifecycleService.createInvitation`; resend endpoint
  added). WS5 added **EN/TR i18n** + tenant name to the body: signature is now
  `sendGuestInvitation(to, token, accessStart, accessEnd, message, inviterName,
  tenantName, locale)`; `InviteGuestRequest` carries an optional `locale` ("tr"/"en",
  EN fallback) the admin UI passes; the link is `{frontend}/accept-invite?token=…`.
  (The web accept-invite page still needs to exist for the loop to fully close —
  frontend WS item.) FACE/VOICE enrollment quality/liveness scores were also fixed
  separately (P1-3, PR #137).
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

Active backlog and follow-ups are tracked as GitHub issues on
`Rollingcat-Software/identity-core-api` (the #211 deferred authz follow-ups are
#231 FORCE-RLS + #232 target-aware `RbacPermissionEvaluator`).
