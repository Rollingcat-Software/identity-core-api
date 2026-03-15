# CLAUDE.md - Identity Core API

## Project Overview

Java 21 / Spring Boot 3.2+ backend API for the FIVUCSAS biometric identity platform.
Hexagonal Architecture with Ports and Adapters pattern.

## Build & Test

```bash
./gradlew clean build          # Build
./gradlew bootRun              # Run (dev)
./gradlew test                 # Run tests
./gradlew test jacocoTestReport # Coverage
```

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

See TODO.md for full integration audit (49 items).
