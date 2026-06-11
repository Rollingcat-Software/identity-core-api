# Authorization IDOR / PII-leak / abuse-throttle fixes — 2026-06-07

Branch: `claude/fix-authz-idors`. All changes are application-layer object-level
authorization guards, a defense-in-depth tenant column, Turkish-locale casing
corrections, and a per-identifier OTP-send throttle. No JWT/OAuth2 `cross_tenant`
or WebAuthn behavior was touched (audited sound). No secrets rotated. No DB role
or RLS change (see Deferred).

## Threat model

Several endpoints performed **authentication** (`isAuthenticated()`) or
**permission-only** authorization (`hasPermission(resource, action)`) but no
**object-level** authorization — i.e. they trusted a body- or path-supplied
`userId`/`id` without checking that the caller owns the target or may manage the
target's tenant. The `RbacPermissionEvaluator` for `hasPermission(#userId, type,
action)` ignores the `#userId` argument entirely; it only answers "does the caller
hold `type:action`?". Because a TENANT_ADMIN holds every tenant-scoped permission
implicitly, permission-only gates collapse to "any admin can act on any tenant's
objects". These are classic IDOR / cross-tenant access bugs.

## Fixes

| # | Severity | Endpoint / method | Guard added | Test |
|---|----------|-------------------|-------------|------|
| 1 | CRITICAL | `POST /nfc/enroll` → `ManageNfcCardService.enrollCard` | self OR `device:create` admin + target tenant in caller scope; `reauthorize` always requires `device:create` (not the body flag) | `ManageNfcCardServiceTest`: `enrollCard_WhenNonOwnerWithoutAdminPermission_ShouldThrowUnauthorized`, `enrollCard_WhenReauthorizeWithoutAdminPermission_ShouldThrowUnauthorized`, `enrollCard_WhenAdminTargetsForeignTenant_ShouldThrowUnauthorized` |
| 2 | HIGH | `DELETE /nfc/{userId}` → `removeAllUserEnrollments` | self OR `device:create` admin + target tenant in scope | `removeAllUserEnrollments_WhenNonOwnerWithoutAdminPermission_ShouldThrowUnauthorized`, `removeAllUserEnrollments_WhenAdminInTenant_ShouldDeactivate` |
| 3 | HIGH | `/users/{userId}/settings` (+ sub-resources) | `UserController.assertCanAccessUserSettings` (self OR target tenant in scope) + `tenant_id` (V84) + `@Filter(tenantFilter)` on `UserSettings` | `UserSettingsAuthzTest` (5 tests incl. cross-tenant SECURITY-section read) |
| 4 | HIGH | `POST /enrollments/{id}/retry`, `DELETE /enrollments/{id}` | re-check `enrollment.getTenant()` vs `tenantScopeResolver.currentScope()` (404 for foreign row) | `EnrollmentControllerTest`: `retryEnrollment_WhenCrossTenantCaller_ShouldReturnNotFoundAndNotSave`, `deleteEnrollment_WhenCrossTenantCaller_ShouldReturnNotFoundAndNotDelete` |
| 5 | MED | `POST /devices/push-token` | bind to authenticated principal (`SecurityContextHolder` → `findByEmail`), ignore body `userId` | covered by the ArchUnit boundary + manual review (controller-level principal bind) |
| 6 | MED | `POST /nfc/verify`, `GET /nfc/user/{userId}` | `@PreAuthorize("@rbac.hasPermission('device:read')")` on verify; service tenant-scopes verify + listUserCards (self OR `device:read` admin in tenant) | `verifyCard_WhenCardInForeignTenant_ShouldReturnEmpty`, `verifyCard_WhenCardInOwnTenant_ShouldReturnCard`, `listUserCards_WhenNonOwnerWithoutReadPermission_ShouldThrowUnauthorized`, `listUserCards_WhenOwner_ShouldReturnCards` |
| 7 | MED | `Locale.ROOT` on security case-folds | `RbacPermissionEvaluator`, `entity.Permission`, `domain.model.permission.Permission`, `entity.User.hasAnyRole`, `domain.model.user.User.hasAnyRole`, `BiometricConsentService`, `AuthSessionController`, **`NfcSerial.canonicalize`** | `TurkishLocalePermissionCasingTest` (forces tr-TR); `NfcSerialTest` + `NfcDocumentAuthHandlerTest` now pass on a tr-TR JVM |
| 8 | MED | OTP-send throttle on `/auth/mfa/send-otp`, `/auth/2fa/send`, `/auth/2fa/send-sms`, `/auth/send-phone-verification` | `OtpService.acquireSendSlot` — per-identifier (per-victim) Redis bucket, 3/min, fails open | `OtpServiceTest$SendThrottle` (over-cap → 429, TTL on first send, fails-open on Redis error) |

### Notes on specific choices

- **NFC admin permission = `device:create`** (and read = `device:read`): an NFC
  card is a physical credential/device, reusing the same permission family already
  on `/search/{serial}`. No new permission was minted.
- **404 vs 403 on cross-tenant enrollment** (fix 4): we return 404 for a
  foreign-tenant row to avoid a cross-tenant id-existence oracle, matching the
  existing `getEnrollmentById` shape.
- **OTP throttle placement** (fix 8): the spec suggested `RateLimitFilter`/
  `SecurityConfig`, but the throttle was implemented at the service layer. The
  filter only sees IP + path (not the resolved victim user/identifier), and the
  abuse we care about is per-victim SMS/email flooding from a single NAT'd IP. The
  service-layer bucket keys on the OTP identifier (which embeds the target user id),
  giving per-victim throttling regardless of source IP. Fails OPEN on Redis error
  so a Redis blip never locks a legitimate user out of receiving any OTP.
- **`NfcSerial.canonicalize`** (fix 7) was NOT in the original list but is a genuine
  Turkish-locale bug in a security identifier: on a tr-TR JVM an opaque serial
  `"VALIDSERIAL"` canonicalized to `"VALİDSERİAL"`, so a stored card would never
  match a verify (auth denial). Found because the local JVM default locale is tr-TR;
  `NfcSerialTest`/`NfcDocumentAuthHandlerTest` were failing on clean `main` before
  the fix.

## Flyway V84

`V84__user_settings_tenant_id.sql` — additive, idempotent, metadata-only:
adds nullable `user_settings.tenant_id`, backfills from `users.tenant_id`, adds a
guarded FK to `tenants(id) ON DELETE CASCADE`, and an index. The application-layer
guard (`assertCanAccessUserSettings`) is the PRIMARY control; the `@Filter` is
defense-in-depth, matching the 8 entities hardened in P0-1. Latest prior migration
was V83.

## ArchUnit baseline (`archunit_store/08c0f28b-...`) verdict

The `entity.User` boundary is enforced by `UserDomainBoundaryTest` via
`FreezingArchRule`, which matches frozen violations **by exact line number**. The
checked-in baseline on `main` had drifted stale: production code moved
independently of this task (notably `OAuth2Service.exchangeCode` was refactored to
`buildTokenResponse`/`refreshAccessToken`, plus line shifts in `UserResponseMapper`,
`UsernamelessLoginFlowService`, `ApproveLoginVerifyMfaStepHandler`,
`NfcDocumentVerifyMfaStepHandler`, `ManageDeviceService`, `ManageEnrollmentService`,
`ManageUserService`, etc. — none touched by this task). Running the rule against
the stale baseline reported **63 spurious "new" violations**, almost all pure
line-number churn in classes this task never modified.

Per the task directive, the baseline was first reverted (`git checkout`) and the
rule re-run to establish the real state, then refrozen
(`-Darchunit.freeze.refreeze=true`). A line-number-agnostic diff of the refrozen
baseline vs the previous one confirms the only **net-new** boundary crossings
introduced by THIS task are justified by the security fixes:

- `ManageNfcCardService.assertTargetWithinManageableTenant(...)` (new helper)
- `ManageNfcCardService.enrollCard(...,boolean,String)` (new overload from the
  reauthorize-as-permission refactor)
- `ManageNfcCardService.listUserCards(...)` (new guard)
- `DeviceController.updatePushToken(...)` references `User.getId()` (fix 5)

All other net-new entries (OAuth2Service, the MFA handlers, etc.) are **pre-existing
`main` drift** that the stale baseline simply hadn't captured — not new debt hidden
by this change. The baseline did grow (604→653 raw lines), but the growth is
line-number churn + pre-existing-unfrozen violations, not masking of new
unjustified crossings.

## Verification

- `JAVA_HOME=jdk-21`, `mvn -o` (offline). JVM default locale on the build box is
  **tr-TR**, which is stricter than CI (`en_US`) and surfaces latent locale bugs.
- **Focused suite** (`*Nfc*,*Enrollment*,*UserController*,*UserSettings*,*Device*,
  *Permission*,*UserDomainBoundary*,*OtpService*,*TurkishLocale*,
  *RbacPermissionEvaluator*,NfcSerialTest,NfcDocumentAuthHandlerTest`):
  **182 run, 0 failures, 0 errors, 0 skipped.**
- **Full suite** (`mvn -o test`): **1666 run, 3 failures, 1 error, 67 skipped.**
  - 67 skips = Docker/Testcontainers integration tests (expected, Docker-off).
  - The 4 failures are **pre-existing on clean `main`** (verified by stashing all
    changes and running the same tests on `main`), locale-independent, and
    unrelated to this task:
    - `OAuth2ServiceTest.exchangeCode_WhenValidCode_ShouldReturnTokens` — ID-token
      `aud` claim assertion (`aud=null` vs `client-1`). Pre-existing OAuth2 test
      rot; JWT/OAuth2 was explicitly out of scope.
    - `WebAuthnCredentialServiceTest$SaveCredential.{platformTransportTriggers...,
      roamingTransportTriggers..., swallowsEnrollmentFailure}` — Mockito
      contract mismatch (`completeEnrollment` vs `autoBindEnrollment`). Pre-existing
      test rot.
  - No assertion was weakened to make anything pass.

## Deferred follow-ups

- **Postgres `FORCE ROW LEVEL SECURITY` / DB-role change.** The DB superuser role
  is shared across ~6 apps (per infra notes); adding `FORCE RLS` or changing the
  role is an infrastructure task with cross-app blast radius, deliberately NOT done
  here. The `@Filter(tenantFilter)` + application guards are the in-app controls.
- **`RbacPermissionEvaluator` target-awareness.** `hasPermission(#userId, type,
  action)` still ignores `#userId` globally; this task closed the specific
  user-settings hole at the object level rather than re-architecting the evaluator.
  A generic target-aware evaluator (or consistently pairing permission gates with
  object guards) is a larger follow-up.
- **OAuth2 `aud` claim + WebAuthn enrollment-binding test rot** surfaced above are
  pre-existing and should be triaged separately (out of scope for the authz fixes).
