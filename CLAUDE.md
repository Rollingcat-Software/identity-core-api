# CLAUDE.md - Identity Core API

## Project Overview

Java 21 / Spring Boot 3.2.0 backend API for FIVUCSAS biometric identity platform.
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

## Key Patterns

- **N-step MFA**: JWT deferred until all steps complete. `POST /auth/mfa/step` with session token. RFC 8176 `amr` claim.
- **WebAuthn base64**: `decodeBase64()` normalizes standard→URL-safe. NEVER use `Base64.getUrlDecoder()` on frontend data.
- **Session path handlers**: Accept BOTH old and new field names for backward compatibility (B1-B6).
- **Entity state**: Professional pattern — NfcCard/OAuth2Client use `revokedAt` timestamps, User `isActive` synced from status enum via `@PrePersist/@PreUpdate`.
- **NFC enrollment**: Auto-creates user_enrollments record. Reactivates existing inactive card on re-enrollment.
- **CORS**: api.fivucsas.com, app.fivucsas.com, demo.fivucsas.com, verify.fivucsas.com

## Flyway Migrations (V1-V32)

V1-V15: Core schema | V16: Auth methods/flows | V17: Devices | V24: OAuth2 | V25: Enrollments
V26-V28: Verification pipeline | V29: EMAIL_OTP default | V30: Adaptive MFA (CHOICE steps)
V31: display_order fix | V32: Entity professionalization (revokedAt, expiresAt, verifiedAt)

## Cross-Repo Dependencies

- **biometric-processor** (Python/FastAPI, port 8001) — internal Docker network only, `X-API-Key` header
- **web-app** (React) consumes this API
- **SMTP**: `smtp.hostinger.com:587`, sender `info@app.fivucsas.com`, creds in `.env.prod`

See TODO.md for integration audit (49 items).
