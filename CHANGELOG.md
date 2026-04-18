# Changelog - Identity Core API

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

## [Unreleased] - 2026-03-07

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
