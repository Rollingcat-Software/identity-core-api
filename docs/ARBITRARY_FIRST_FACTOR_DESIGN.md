# Arbitrary First-Factor Login — Design / Scope

**Status:** Proposed (scoping). 2026-05-31.
**Goal:** Let a user satisfy a CHOICE Layer-1 step with **any allowed method**
(e.g. start with Face, TOTP, or Email-OTP) instead of always being forced to
password — on both `verify.fivucsas.com` (hosted) and `app.fivucsas.com`
(dashboard). Today both surfaces fall back to PASSWORD whenever PASSWORD is one
of the Layer-1 choices (`pickInitialPhase → FlowPhase.Password`;
`AuthenticateUserService` is password-entry only).

## TL;DR — most of this already exists

The N-step MFA machinery is method-agnostic and complete:

- **Every method has a step handler** under
  `application/service/mfa/handler/` — incl. `PasswordVerifyMfaStepHandler`
  (verifies the raw password via `user.checkPassword`). So step 1 can be ANY
  method, password included.
- `VerifyMfaStepService.execute` resolves the **current step's** allowed method
  set (`resolveCurrentStepMethodNames`) and accepts any method valid there, for
  ANY step including step 1. It advances `currentStep`, records
  `completedMethods`, and mints tokens only when the flow completes.
- `UsernamelessLoginFlowService.continueAfterLayer1` already bridges a proven
  Layer-1 factor (passkey/approve/QR) into the flow by creating an `MfaSession`
  at `currentStep=2`.
- Enumeration-safe **decoy sessions** for unknown identifiers already exist in
  `ApproveLoginService` (a decoy that can never complete; never indexed).

**The only real gap:** there is no endpoint to OPEN a flow session at
`currentStep=1` for an *identified* user **without first verifying a password**.
The frontend already calls a `POST /auth/login/begin` for this — but that
endpoint **does not exist** (returns 401), so the no-password Layer-1 path is
dead today.

## Backend work

### 1. `POST /auth/login/begin` (the missing endpoint)  — ~½ day
Public (permitAll). Request `{ email, clientId? }`. Behavior:
1. Tenant-eligibility check (reuse `checkTenantEligibility` → 403 TENANT_MISMATCH).
2. Resolve user + default `APP_LOGIN` flow (reuse `resolveHomeTenantId` + flow lookup).
3. Filter step-1's CHOICE methods to those the user can actually use:
   - method is in step 1's available set, AND
   - `!requiresEnrollment` OR the user has a healthy enrollment
     (`EnrollmentHealthService.validateEnrollments`, same as
     `UsernamelessLoginFlowService`).
4. Create an `MfaSession` at **`currentStep=1`, `completedMethods=[]`**,
   `totalSteps=flow.stepCount`, bound to `clientId/ip/ua`, 10-min TTL.
5. Return `{ mfaSessionToken, currentStep:1, totalSteps, availableMethods:[…layer-1…] }`.
6. **Unknown / ineligible email → decoy** session (random token, generic method
   list, never completes — mirror `ApproveLoginService`). No OTP is sent for a
   decoy.

Then the user picks a method and completes step 1 via the **existing**
`POST /auth/mfa/step` — no new verification code. Single-step flows mint tokens
on that one call; multi-step flows continue 2..N exactly as today.

New service method (place the user/entity access in `AuthenticateUserService`,
which already legitimately depends on `entity.User`, to stay within the
`UserDomainImportBoundaryTest` ArchUnit freeze).

### 2. Rate-limit / lockout parity  — ~¼ day
Password login has lockout (`AccountLockedException`). `/auth/login/begin` must
throttle per-identifier+IP (begin attempts) so it can't be used to spray OTP
sends or brute biometric attempts. Per-method OTP attempt budgets already exist
(`OtpAttemptsExhaustedException`); reuse them. The lockout counter that password
login increments should also apply when a password step-1 fails via `/mfa/step`.

### 3. Feature flag  — ~0
Gate behind the existing config-driven engine (or a new
`app.auth.arbitrary-first-factor`), default **OFF**, dark → canary one tenant →
global, revert by env var (no redeploy). Matches the
[reversible-risky-change] rule for login paths.

## Frontend work — ~1 day

- **`AuthRepository.beginIdentifierLogin`** already targets `/auth/login/begin`
  and maps the response — it just needs the live endpoint (no client change).
- **verify-app `LoginMfaFlow.tsx`**: change `pickInitialPhase` so that when
  Layer-1 is a CHOICE with >1 method, the identifier step routes to
  `FlowPhase.MethodPicker` (render the Layer-1 method set) instead of forcing
  `FlowPhase.Password`. On pick: PASSWORD → password step; any other →
  `beginIdentifierLogin` (open step-1 session) then `TwoFactorDispatcher` for
  the chosen method. `MethodPickerStep` already renders the choices.
- **dashboard `LoginPage.tsx`**: same Layer-1 picker, reusing the
  `flowTotalSteps` step counter shipped 2026-05-31. Password remains the default
  highlight; other methods become selectable.
- i18n: method-picker labels already exist (`auth.methodLabels.*`).

## Policy: the TENANT's flow is the policy — no artificial method limits

**Decided 2026-05-31 (operator):** do NOT hardcode any backend restriction on
which methods may be a first/sole factor. The whole point is "all configured
methods are usable." The tenant already chooses the security level by how they
design the flow (1 step vs. multi-step, which methods in Layer-1); the platform
must honor that and not second-guess it. A tenant who wants a stronger bar adds a
step; one who allows OTP-only login has made that call.

What we DO enforce (abuse hygiene, not user-choice limits — applies regardless):
- **Enrollment filter** — only offer Layer-1 methods the user has a healthy
  enrollment for (`requiresEnrollment` ⇒ must be enrolled).
- **Decoy sessions** for unknown/ineligible identifiers (mirror
  `ApproveLoginService`) — no account-existence oracle; no OTP sent for a decoy.
- **Rate-limiting** on `/auth/login/begin` (per identifier+IP) + the existing
  per-method OTP attempt budgets; password step-1 failures feed the existing
  lockout counter.
- Biometric liveness / anti-spoof already enforced on `/verify`.
- (Optional, future) a non-blocking WARNING in the auth-flow builder when a
  1-step flow allows a weak sole factor — guidance, not a hard block.

## Effort & risk

- **~2–2.5 days** total (≈1 backend, ≈1 frontend, ≈½ tests + canary).
- **Low structural risk** — reuses the existing handler/session/token machinery;
  the new endpoint is additive and flag-gated; legacy password login is
  untouched when the flag is OFF.
- **Test plan:** unit (begin endpoint: enrolled-filter, decoy, tenant-lock),
  the existing `/mfa/step` handlers are already covered, an integration test for
  a face-first → totp-second → done flow, and a canary tenant before global.

## Out of scope / follow-ups
- Per-tenant policy for "which methods may be a sole first factor" (a config
  surface in the auth-flow builder) — could ship after the core.
- Remembering a user's preferred first factor across logins.
