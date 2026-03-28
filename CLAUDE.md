# CLAUDE.md - Identity Core API

## Project Overview

Java 21 / Spring Boot **3.2.0** backend API for the FIVUCSAS biometric identity platform.
Hexagonal Architecture with Ports and Adapters pattern.
Production URL: https://auth.rollingcatsoftware.com

## Build & Test

```bash
# Local (Maven — gradle not used in this project)
mvn clean package -DskipTests
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Production (Docker — Maven is NOT installed on VPS)
cd /opt/projects/fivucsas/identity-core-api
docker compose -f docker-compose.prod.yml --env-file .env.prod build --no-cache identity-core-api
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d identity-core-api
```

⚠️ **Always use `--env-file .env.prod`** when running docker compose on VPS or all env vars will be blank (blank POSTGRES_PASSWORD, JWT_SECRET, MAIL_*, etc.).

Runs on port 8080. Swagger UI at `/swagger-ui.html`.

## Key Directories

- `src/main/java/com/fivucsas/identity/controller/` - REST controllers (23 controllers)
- `src/main/java/com/fivucsas/identity/application/service/handler/` - Auth method handlers
- `src/main/java/com/fivucsas/identity/application/port/output/` - Output ports (BiometricServicePort)
- `src/main/java/com/fivucsas/identity/infrastructure/` - Adapters (BiometricServiceAdapter, WebAuthn)
- `src/main/java/com/fivucsas/identity/infrastructure/adapter/BiometricServiceAdapter.java` - HTTP client for biometric-processor (face, voice)
- `src/main/java/com/fivucsas/identity/infrastructure/webauthn/` - WebAuthn service (fingerprint, hardware key)
- `src/main/java/com/fivucsas/identity/entity/` - JPA entities
- `src/main/java/com/fivucsas/identity/repository/` - Spring Data repositories

## Auth Method Handlers

All handlers in `application/service/handler/`:
- PasswordAuthHandler, EmailOtpAuthHandler, SmsOtpAuthHandler, TotpAuthHandler
- QrCodeAuthHandler, FaceAuthHandler, FingerprintAuthHandler, VoiceAuthHandler
- NfcDocumentAuthHandler, HardwareKeyAuthHandler

## Known Issues (March 2026)

### Auth handler status (2026-03-28):
1. **PasswordAuthHandler** — WORKING
2. **EmailOtpAuthHandler** — WORKING (SMTP via Hostinger)
3. **SmsOtpAuthHandler** — WORKING (NoOpSmsService, Twilio ready for activation)
4. **TotpAuthHandler** — WORKING
5. **QrCodeAuthHandler** — WORKING
6. **FaceAuthHandler** — WORKING (calls biometric-processor DeepFace)
7. **FingerprintAuthHandler** — WORKING (WebAuthn assertion via WebAuthnService, 2026-03-28 fix)
8. **VoiceAuthHandler** — WORKING (calls biometric-processor Resemblyzer)
9. **HardwareKeyAuthHandler** — WORKING (WebAuthn cross-platform)
10. **NfcDocumentAuthHandler** — WORKING (backend logic complete, needs mobile client)

### Connected integrations (March 2026):
- TotpController connected to frontend TotpEnrollment (setup, verify, status, disable)
- QrCodeController connected to frontend QrCodeStep (generate, invalidate, auto-refresh)
- GuestController connected to frontend GuestsPage (invite, extend, revoke, list)
- Forgot/Reset password endpoints connected to frontend pages

### Missing integrations:
- EnrollmentManagementController per-user endpoints unused by frontend
- UserController.getAllUsers() uses in-memory pagination (fetches all, then slices) - works but inefficient for large datasets

### Security hardening (March 2026):
- JWT blacklist: fail-closed on null JTI (JwtAuthenticationFilter rejects tokens without JTI)
- Logout: throws IllegalStateException if access token has no JTI claim
- Redis event bus: uses @EventListener(ContextRefreshedEvent) instead of @PostConstruct
- CORS: docker-compose.prod.yml includes ica-fivucsas subdomain
- Flyway: production config with baseline-on-migrate

### Cross-repo dependencies:
- Communicates with **biometric-processor** (Python/FastAPI on port 8001) via BiometricServiceAdapter
- Consumed by **web-app** (React frontend on port 3000) via REST API

### Session 2026-03-28 fixes:
- **FingerprintAuthHandler rewrite** — Removed BiometricServicePort dependency (stub). Now uses WebAuthnService + WebAuthnCredentialRepositoryPort for WebAuthn platform authenticator assertions. Supports challenge generation with `authenticatorAttachment: "platform"`. Tests rewritten (10 test cases).
- **Docker image rebuilt and deployed** — identity-core-api container rebuilt with FingerprintAuthHandler fix, running healthy on Hetzner VPS.

### Critical fixes applied (2026-03-16):
- **`@AutoConfigureMockMvc`** import path: `org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc` (Spring Boot 3.x path)
- **`AuditLogAdapter.logUserRegistered()`** — changed from `REQUIRES_NEW` to `REQUIRED` propagation. `REQUIRES_NEW` opens an isolated transaction that cannot see the uncommitted user row, causing `audit_logs.user_id` FK violation on every registration.
- **`MinioMediaStorageAdapter`** `@PostConstruct` — wrapped bucket existence check in try-catch so Spring context loads without MinIO available in test env
- **Flyway V14** — added `DROP INDEX IF EXISTS idx_messages_expires_at` before recreating (V6 already created it on fresh DBs)
- **SMTP mail** — Spring Boot only auto-configures `JavaMailSender` via `spring.mail.host`, NOT custom `mail.host`. Use `SPRING_MAIL_*` env vars in `docker-compose.prod.yml`

### Email OTP (production, 2026-03-16):
- SMTP: `smtp.hostinger.com:587` with STARTTLS
- Sender: `info@ica-fivucsas.rollingcatsoftware.com`
- Credentials stored in `.env.prod` as `MAIL_*` + `SPRING_MAIL_*`

See TODO.md for full integration audit (49 items).
