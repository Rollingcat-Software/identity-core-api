# Findings — Tests & Security (2026-06-07)

Session scope: green up the offline unit/slice + ArchUnit test suite, and record a
security de-escalation on the previously-flagged `.env.hetzner` leak. **This document
contains NO secret values.**

---

## 1. Test fixes

### Environment / how it was run
- JDK 21 (`JAVA_HOME=C:\Program Files\Java\jdk-21`). The default `java` on PATH is
  JDK 8 and will fail the build — JDK 21 is mandatory.
- `mvn -o test` (offline; the `~/.m2` cache already had the deps, so no slow cold
  resolution was needed).
- Build/runtime default locale is `tr_TR` — relevant to the NFC fix below.
- Docker is OFF locally, so Testcontainers/DB integration tests cannot run; they are
  reported as **skipped**, not failures.

### 1a. WebAuthn — `completeEnrollment` → `autoBindEnrollment` rename reconciliation (this session)

**Root cause.** `WebAuthnCredentialService.autoCompleteWebAuthnEnrollment(...)`
(`src/main/.../application/service/WebAuthnCredentialService.java`) was migrated to call
the idempotent, own-transaction (`REQUIRES_NEW`) upsert
`ManageEnrollmentUseCase.autoBindEnrollment(userId, methodType)` — the create-if-missing
binding that fixed the first-time-fingerprint `UnexpectedRollbackException`
("Beklenmeyen bir hata"), because the old `completeEnrollment` only completed a
pre-existing PENDING row and threw "Enrollment not found" into the credential-save
transaction. The test class `WebAuthnCredentialServiceTest` still verified/stubbed the
**removed** 3-arg call `completeEnrollment(userId, methodType, "{}")`.

**Failing tests (3) — exact names and cause:**

| Test (`WebAuthnCredentialServiceTest$SaveCredential`) | Failure | Cause |
|---|---|---|
| `platformTransportTriggersFingerprintEnrollment` | `Wanted but not invoked: completeEnrollment(uuid, FINGERPRINT, "{}")` (got `autoBindEnrollment(uuid, FINGERPRINT)`) | test asserted the removed method |
| `roamingTransportTriggersHardwareKeyEnrollment` | `Wanted but not invoked: completeEnrollment(uuid, HARDWARE_KEY, "{}")` (got `autoBindEnrollment(uuid, HARDWARE_KEY)`) | test asserted the removed method |
| `swallowsEnrollmentFailure` | `UnnecessaryStubbingException` on `completeEnrollment(any,any,any)` | stub for a method production no longer calls |

**Fix.** Updated the **test** to match the current production API
(`autoBindEnrollment(userId, methodType)` — 2 args, no `"{}"` data). Production code was
**not** changed. No authentication/crypto/security semantics were touched. The separate
`ManageEnrollmentUseCase.completeEnrollment(...)` overloads remain in use by the
start→complete enrollment flow and are unaffected.

File changed: `src/test/java/com/fivucsas/identity/application/service/WebAuthnCredentialServiceTest.java`.

### 1b. Pre-existing fixes carried in on this branch (commit `415469d`)

These were already committed/pushed before this session and were verified still-green:

- **NFC serial Turkish-locale casing** — `domain.model.NfcSerial` canonicalize now uses
  `toUpperCase(Locale.ROOT)`. Under `tr_TR`, bare `toUpperCase()` maps `i → İ`, which
  would corrupt a hex serial and break cross-client (mobile UPPERHEX vs web
  lowercase-with-colons) match.
- **OAuth2 token mint off `entity.User`** — introduced `OAuth2TokenMintPort` +
  `infrastructure/oauth2/OAuth2TokenMintAdapter` so OAuth2 minting no longer imports the
  `entity.User` JPA type, satisfying the `UserDomainImportBoundaryTest` ArchUnit rule. No
  change to minted token contents.

### Final result

```
mvn -o test
Tests run: 1648, Failures: 0, Errors: 0, Skipped: 67
BUILD SUCCESS
```

The 67 skipped are all Testcontainers/DB integration tests, not runnable locally with
Docker off (e.g. `*IntegrationTest`, `AuditLogPgPartmanMigrationTest`,
`ForbidHardDeleteTriggerIntegrationTest`, `TenantRlsRegressionTest`,
`SoftDeletePurgeJobConcurrencyTest`, and the 3 DB-gated cases in `AuthControllerTest`).
Verify those via CI on the self-hosted runner, not on this box. The ArchUnit boundary
tests (pure classpath analysis, no DB) ran as ordinary unit tests and passed.

---

## 2. Security — stale-secret de-escalation for `.env.hetzner`

### Background
The runbook `docs/SECURITY-rotate-credentials-2026-06-06.md` flagged the git-tracked
`.env.hetzner` file (committed in `f9f0f2d`, already on `origin/main`) as a **HIGH**
severity live-secret leak and prescribed emergency rotation of three secrets
(PostgreSQL password, Redis password, JWT signing secret). A working-tree hygiene fix
landed on branch `claude/untrack-env-hetzner-secret` (`git rm --cached` + hardened
`.gitignore`) to stop future tracking.

### Finding (de-escalation)
The credentials in the leaked git-tracked `.env.hetzner` (commit `f9f0f2d` on
`origin/main`) are **STALE GCP-era credentials, NOT the live production secrets.** This
was verified by SHA-256 fingerprint: the leaked values' fingerprints match the OLD
(decommissioned-GCP) credential set, and do **not** match the current Hetzner
production secret set. The live secrets reside in `.env.prod`, which has **never been
committed** to the repository (it is host-local on the Hetzner box and blocked by
`.gitignore`).

**Consequence:** the emergency rotation prescribed by the 2026-06-06 runbook was **NOT
required** — the exposed material is inert (it authenticates against infrastructure that
no longer exists). The runbook's severity was therefore over-stated for this specific
leak; it remains valid as the procedure to follow *if live secrets are ever leaked*.

### What still stands (hygiene, not emergency)
- Keep `.env.hetzner` untracked + gitignored going forward — the
  `claude/untrack-env-hetzner-secret` branch achieves this. This prevents a *future*
  re-leak and removes a confusing stale artifact from the tree.
- A git-history purge of `f9f0f2d` is **not** warranted: the blob holds only inert
  stale creds, and a history rewrite would require a force-push to `main` (hard-blocked
  + branch-protected) and would break every clone/fork.
- Live secrets (`.env.prod`) were never exposed; no rotation, no token invalidation, no
  user re-login event is needed as a result of this leak.

> No secret values, fingerprints, or partial secrets are recorded in this document.
> The fingerprint comparison was performed out-of-band against the known old/new
> credential sets.

### References
- Runbook: `docs/SECURITY-rotate-credentials-2026-06-06.md`
- Hygiene branch: `claude/untrack-env-hetzner-secret`
- Leak commit: `f9f0f2d` (`.env.hetzner` tracked on `origin/main`)
