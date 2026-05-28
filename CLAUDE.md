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

## Flyway Migrations (V1-V60)

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

## Operator reality (2026-05-28 update)

- V60 (drop refresh_tokens.token plaintext) applied in prod. Prod has been rebuilt
  since the 2026-05-04 pending note — V56 through V60 all applied.
- pg_partman (V57) is fail-soft. `ALTER DATABASE identity_core SET app.skip_partman_v57='on'`
  is available for explicit opt-out if partman extension is absent.

## Cross-Repo Dependencies

- **biometric-processor** (Python/FastAPI, port 8001) — internal Docker network only, `X-API-Key` header
- **web-app** (React) consumes this API
- **SMTP**: `smtp.hostinger.com:587`, sender `info@app.fivucsas.com`, creds in `.env.prod`

See TODO.md for integration audit (49 items).
