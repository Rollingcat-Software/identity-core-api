# CLAUDE.md - Identity Core API

## Project Overview

Java 21 / Spring Boot **4.0.2** backend API for the FIVUCSAS biometric identity platform.
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
- `src/main/java/com/fivucsas/identity/entity/` - JPA entities
- `src/main/java/com/fivucsas/identity/repository/` - Spring Data repositories

## Auth Method Handlers

All handlers in `application/service/handler/`:
- PasswordAuthHandler, EmailOtpAuthHandler, SmsOtpAuthHandler, TotpAuthHandler
- QrCodeAuthHandler, FaceAuthHandler, FingerprintAuthHandler, VoiceAuthHandler
- NfcDocumentAuthHandler, HardwareKeyAuthHandler

## Known Issues (March 2026)

### BROKEN auth methods at runtime:
1. **NfcDocumentAuthHandler** - hardcoded to always return failure (line 37-41)
2. **FingerprintAuthHandler** - calls BiometricServicePort.verifyFingerprint() which hits a stub in biometric-processor that always fails
3. **VoiceAuthHandler** - calls BiometricServicePort.verifyVoice() which hits a stub in biometric-processor that always fails

### Connected integrations (March 2026):
- TotpController connected to frontend TotpEnrollment (setup, verify, status, disable)
- QrCodeController connected to frontend QrCodeStep (generate, invalidate, auto-refresh)
- GuestController connected to frontend GuestsPage (invite, extend, revoke, list)
- Forgot/Reset password endpoints connected to frontend pages

### Missing integrations:
- WebAuthnController has registration endpoints but web-app has no enrollment UI
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

### Critical fixes applied (2026-03-16):
- **Spring Boot 4.x `@AutoConfigureMockMvc`** import path changed to `org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc` (NOT the 3.x path `org.springframework.boot.test.autoconfigure.web.servlet`)
- **`AuditLogAdapter.logUserRegistered()`** — changed from `REQUIRES_NEW` to `REQUIRED` propagation. `REQUIRES_NEW` opens an isolated transaction that cannot see the uncommitted user row, causing `audit_logs.user_id` FK violation on every registration.
- **`MinioMediaStorageAdapter`** `@PostConstruct` — wrapped bucket existence check in try-catch so Spring context loads without MinIO available in test env
- **Flyway V14** — added `DROP INDEX IF EXISTS idx_messages_expires_at` before recreating (V6 already created it on fresh DBs)
- **SMTP mail** — Spring Boot only auto-configures `JavaMailSender` via `spring.mail.host`, NOT custom `mail.host`. Use `SPRING_MAIL_*` env vars in `docker-compose.prod.yml`

### Email OTP (production, 2026-03-16):
- SMTP: `smtp.hostinger.com:587` with STARTTLS
- Sender: `info@ica-fivucsas.rollingcatsoftware.com`
- Credentials stored in `.env.prod` as `MAIL_*` + `SPRING_MAIL_*`

See TODO.md for full integration audit (49 items).
