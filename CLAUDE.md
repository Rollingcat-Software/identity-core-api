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

## Flyway Migrations (V1-V43)

V1-V15: Core schema | V16: Auth methods/flows | V17: Devices | V24: OAuth2 | V25: Enrollments
V26-V28: Verification pipeline | V29: EMAIL_OTP default | V30: Adaptive MFA (CHOICE steps)
V31: display_order fix | V32: Entity professionalization (revokedAt, expiresAt, verifiedAt)
V33: voice_enrollments table (deployed 2026-04-14 — unblocked VOICE auth)
V34: oauth2_clients.confidential column (PKCE S256 mandated for public clients — PR-1)
V35: mfa_sessions.consumed_at TIMESTAMP (atomic code-mint replay guard — PR-1 B4)
V36: mfa_sessions.client_id UUID (cross-client replay guard — PR-1 B2)
V37: oauth2_clients.tenant_id index (audit safety-net; V24 already had it)
V38: fivucsas-web-dashboard → confidential=false (SPA cannot hold a secret)
V39: users.two_factor_secret AES-GCM-256 encryption (BE-H3, AUDIT_2026-04-19)
V40: audit_logs monthly RANGE partitioning (IN-H5, AUDIT_2026-04-19)
V41: audit_logs pg_partman maintenance (auto-create partitions)
V42: CHECK constraint — two_factor_secret LIKE 'enc:v1:%' (TOTP strict, PR #17)
V43: DROP TABLE biometric_data (dead-code cleanup, 0 rows in prod; PR #17)

**V34-V43 all applied to prod DB (container rebuilt 2026-04-16, -18, -20).**

## Cross-Repo Dependencies

- **biometric-processor** (Python/FastAPI, port 8001) — internal Docker network only, `X-API-Key` header
- **web-app** (React) consumes this API
- **SMTP**: `smtp.hostinger.com:587`, sender `info@app.fivucsas.com`, creds in `.env.prod`

See TODO.md for integration audit (49 items).
