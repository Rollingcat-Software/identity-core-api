# Identity Core API - Deep Audit Report

**Audit Date:** February 25, 2026
**Auditor:** Claude Code (Opus 4.6)
**Scope:** Complete readiness assessment for auth customisation, endpoints, and production deployment
**Branch:** claude/audit-auth-module-w4OTU

---

## Executive Summary

The Identity Core API has achieved **significant architectural maturity** since the initial design analysis (Nov 2025). The hexagonal architecture is properly implemented with 19 input ports, 5 output ports, and 19 REST controllers covering ~85 endpoints.

However, **the module is NOT production-ready**. This audit identifies **7 critical blockers**, **12 high-priority gaps**, and **9 medium-priority improvements** that must be addressed before a client application can reliably connect to and use this module.

### Overall Readiness Score: 62/100

| Category | Score | Status |
|----------|-------|--------|
| Password Auth | 75/100 | Functional but missing forgot/reset |
| Face Auth | 80/100 | Fully functional via BiometricServicePort |
| Fingerprint Auth | 45/100 | Verify-only, no enrollment endpoint |
| Multi-Step Auth Flows | 70/100 | Working but session routing is broken |
| RBAC / Authorization | 75/100 | Hierarchical RBAC working, 3 controllers missing @PreAuthorize |
| Multi-Tenancy | 70/100 | TenantContext + Hibernate filters working, some controllers unscoped |
| Production Security | 60/100 | Rate limiting active, audit persists to DB, gaps in headers |
| Client Integration | 40/100 | No SDK, no OpenAPI spec validation |
| Testing | 65/100 | Good unit tests, weak integration tests |
| Documentation | 80/100 | Comprehensive but outdated |

---

## CRITICAL BLOCKERS (Must Fix Before Any Client Integration)

### CRITICAL-1: Auth Session Sub-Endpoints Require Authentication (BUG)

**File:** `config/SecurityConfig.java:69`

**Problem:** Only `POST /api/v1/auth/sessions` is listed as `permitAll()`. However, the multi-step authentication flow requires ALL session sub-endpoints to be public:
- `GET /api/v1/auth/sessions/{sessionId}` - Check session status
- `POST /api/v1/auth/sessions/{sessionId}/steps/{stepOrder}` - Complete step (e.g., submit password)
- `POST /api/v1/auth/sessions/{sessionId}/steps/{stepOrder}/skip` - Skip optional step
- `POST /api/v1/auth/sessions/{sessionId}/cancel` - Cancel session

These endpoints match `/api/v1/**` which requires `.authenticated()`. A client starting a multi-step login flow can create a session but CANNOT complete any steps because they don't have a JWT token yet.

**Impact:** Multi-step authentication (the core customisable flow) is completely broken for unauthenticated users.

**Fix Required:**
```java
.requestMatchers("/api/v1/auth/sessions", "/api/v1/auth/sessions/**").permitAll()
```

---

### CRITICAL-2: No Fingerprint Enrollment Endpoint

**Problem:** The `BiometricServicePort` interface defines:
- `enrollFace()` - Has dedicated endpoint in `BiometricController`
- `verifyFace()` - Has dedicated endpoint in `BiometricController`
- `verifyFingerprint()` - Has handler in `FingerprintAuthHandler`
- `verifyVoice()` - Has handler in `VoiceAuthHandler`

But there is **NO `enrollFingerprint()` method** on the port, and **NO fingerprint enrollment endpoint** in any controller. The `FingerprintAuthHandler` requires enrollment (`requiresEnrollment() = true`), but there's no way to actually enroll a fingerprint.

**Impact:** Fingerprint authentication is completely unusable - users cannot enroll, so they can never authenticate.

**Fix Required:**
1. Add `enrollFingerprint(UUID userId, String fingerprintData)` to `BiometricServicePort`
2. Add `enrollVoice(UUID userId, String voiceData)` to `BiometricServicePort`
3. Add fingerprint and voice enrollment endpoints to `BiometricController` or `EnrollmentManagementController`
4. Implement adapter methods in `BiometricServiceAdapter`

---

### CRITICAL-3: No Password Forgot/Reset Flow

**Problem:** There are NO endpoints for:
- `POST /api/v1/auth/forgot-password` - Request password reset email
- `POST /api/v1/auth/reset-password` - Reset password with token

The `RateLimitService` already has `PASSWORD_RESET` rate limiting buckets defined (3 per hour per IP), but no endpoint uses them. The `EmailService` interface exists with `NoOpEmailService` and `SmtpEmailService` implementations, but no password reset logic is wired.

**Impact:** Users who forget their password have no self-service recovery path. This is a basic requirement for any production auth system.

---

### CRITICAL-4: UserSettingsController Has No Authorization

**File:** `controller/UserSettingsController.java`

**Problem:** All 8 endpoints in `UserSettingsController` lack `@PreAuthorize` annotations. Any authenticated user can read/modify ANY user's settings by changing the `{userId}` in the URL. This includes security settings like `twoFactorEnabled` and `sessionTimeout`.

**Current:** No authorization at all - any user can change any user's settings
**Required:** At minimum `@PreAuthorize("hasPermission(#userId, 'user_settings', 'read/write') or @userSecurityService.isCurrentUser(#userId)")`

---

### CRITICAL-5: AuditLogController Has No Authorization

**File:** `controller/AuditLogController.java`

**Problem:** Audit log endpoints have no `@PreAuthorize` annotations. Although the security config requires authentication for `/api/v1/audit-logs/**`, any authenticated user can read all audit logs including:
- Failed login attempts with IP addresses
- Other users' registration events
- All biometric operations

This is an information disclosure vulnerability.

**Required:** `@PreAuthorize("hasPermission(null, 'audit', 'read')")`

---

### CRITICAL-6: EnrollmentController Has No Authorization and Bypasses Hexagonal Architecture

**File:** `controller/EnrollmentController.java`

**Problems:**
1. No `@PreAuthorize` annotations - any authenticated user can view/delete ANY enrollment
2. Directly injects `BiometricDataRepository` instead of using use cases
3. `retryEnrollment()` is a stub - returns enrollment data without actually retrying
4. Multiple TODO items indicating incomplete data mapping (quality score, liveness score, error tracking)
5. No tenant scoping - leaks cross-tenant enrollment data

---

### CRITICAL-7: Auth Logout Endpoint Listed Without Authentication

**File:** `controller/AuthController.java:81`

**Problem:** The logout endpoint (`POST /api/v1/auth/logout`) does NOT require authentication in the controller itself and takes `RefreshTokenRequest` in body. While `SecurityConfig` lists it as `.authenticated()`, the controller also doesn't validate that the refresh token belongs to the authenticated user - any user could revoke any refresh token if they know the token value.

---

## HIGH-PRIORITY GAPS

### HIGH-1: AuditLogAdapter Not Wired Into Use Case Services

**Current State:** The `AuditLogAdapter` now properly persists to the database (improved from the Dec 2025 report). However, it is still NOT injected into any use case service.

**Services that should use AuditLogPort but don't:**
- `RegisterUserService` - Should log user registration
- `AuthenticateUserService` - Should log successful/failed authentication
- `LogoutUserService` - Should log logout events
- `EnrollBiometricService` - Should log biometric enrollment
- `VerifyBiometricService` - Should log biometric verification
- `ManageUserService` - Should log user CRUD operations
- `ManageRoleService` - Should log role changes

---

### HIGH-2: EventPublisherAdapter Not Wired Into Any Service

The `EventPublisherPort` and `EventPublisherAdapter` exist but are never used. Domain events like `UserRegistered`, `UserAuthenticated`, `BiometricEnrolled` are not being published.

---

### HIGH-3: Legacy Dead Code Still Present

4 legacy service files from pre-hexagonal refactoring remain:
- `service/AuthService.java` (156 lines)
- `service/UserService.java`
- `service/BiometricService.java`
- `service/StatisticsService.java`

These create confusion and should be deleted. Only `service/RefreshTokenService.java` is still actively used.

---

### HIGH-4: Dual DTO Layer Confusion

Two parallel DTO structures exist:
1. **Legacy:** `dto/` - `RegisterRequest`, `LoginRequest`, `UserDto`, etc. (20 files)
2. **Hexagonal:** `application/dto/command/` and `application/dto/response/` (46+ files)

Controllers use a mix of both. For example:
- `AuthController` uses legacy DTOs (`RegisterRequest`, `LoginRequest`, `AuthResponse`)
- `AuthSessionController` uses hexagonal DTOs (`StartAuthSessionCommand`, `StepResultResponse`)

This creates confusion for client developers about which DTOs are the "real" API contracts.

---

### HIGH-5: RefreshTokenService Not Abstracted as Port

`RefreshTokenService` (in legacy `service/` package) is directly used by hexagonal services like `RefreshAccessTokenService` and `RegisterUserService`. This violates the hexagonal architecture - it should be wrapped as a port/adapter.

---

### HIGH-6: WebAuthn/Hardware Key Only MVP-Level

The `WebAuthnService` does NOT cryptographically verify FIDO2 assertions. The verification is:
```java
boolean valid = credentialId != null && !credentialId.isEmpty()
    && authenticatorData != null && !authenticatorData.isEmpty()
    && signature != null && !signature.isEmpty();
```
This only checks that fields are non-empty. Any string value would pass. This is a security vulnerability if hardware key auth is enabled.

---

### HIGH-7: NFC Document Auth is a Non-Functional Stub

`NfcDocumentAuthHandler` always returns failure. If a tenant configures an auth flow with NFC as a required step, all login attempts will fail with no clear error explanation to the client.

---

### HIGH-8: CORS Allows Swagger/Actuator/H2 in Production

**File:** `SecurityConfig.java:81-90`

`/h2-console/**`, `/swagger-ui/**`, `/actuator/**` are `permitAll()` regardless of environment. The comment says "should be restricted in production" but there's no profile-based restriction.

**Fix:** Use `@Profile("!prod")` or Spring Security profile-aware configuration.

---

### HIGH-9: Session Endpoints Not Tenant-Scoped

`AuthSessionController` endpoints don't validate tenant context. A session started for Tenant A could theoretically be manipulated in a Tenant B context.

---

### HIGH-10: No Email Verification Flow

Users can register with any email address without verification. There's no:
- Email verification token generation
- Email verification endpoint
- Account activation based on email verification

---

### HIGH-11: Missing Exception Handlers for New Domain Exceptions

`GlobalExceptionHandler` doesn't handle several newer domain exceptions:
- `DuplicateRoleException`
- `DuplicateRoleAssignmentException`
- `DuplicateTenantException`
- `SystemRoleModificationException`
- `RoleNotFoundException`
- `PermissionNotFoundException`
- `TenantNotFoundException`
- `InvalidEmailException`

These will fall through to the generic `Exception` handler and return 500 Internal Server Error with an unhelpful message.

---

### HIGH-12: Rate Limiting Not Applied to Auth Endpoints

`RateLimitService` and `RateLimitInterceptor` exist with proper bucket configurations:
- Login: 5 attempts per 15 minutes per IP
- Registration: 3 per hour per IP
- Password reset: 3 per hour per IP

But the interceptor is registered in `WebMvcConfig` - need to verify it's actually intercepting the correct paths and not bypassed by the security filter chain ordering.

---

## MEDIUM-PRIORITY IMPROVEMENTS

### MED-1: BiometricController Only Handles Face

Despite the generic "biometric" naming, `BiometricController` only has face enrollment and verification. Fingerprint, voice, and other biometrics have no dedicated REST endpoints - they only work through the auth session flow.

### MED-2: No Health Check for External Dependencies

`GET /api/v1/auth/health` returns a simple string. It should check:
- Database connectivity
- Redis connectivity
- Biometric service availability
- Email service availability

### MED-3: Integration Tests Are Minimal

Only 2 integration test files exist:
- `AuthenticationFlowIntegrationTest.java`
- `UserApiIntegrationTest.java`

Missing integration tests for: biometric flows, RBAC enforcement, multi-tenancy isolation, auth session flows.

### MED-4: No API Versioning Strategy

All endpoints use `/api/v1/` but there's no versioning strategy, content negotiation, or deprecation mechanism documented.

### MED-5: Application Configuration Not Production-Hardened

`application-prod.yml` should disable:
- Swagger UI
- H2 console
- Debug logging
- Actuator endpoints (or restrict to management port)

### MED-6: No Client SDK or OpenAPI Spec Export

For a module meant to be used by client applications, there's no:
- Generated OpenAPI spec file (only runtime Swagger)
- TypeScript/JavaScript client SDK
- Java client SDK
- API contract tests

### MED-7: Docker Compose Missing Redis

`docker-compose.yml` includes PostgreSQL and the API but Redis configuration may not be complete for all auth handlers that require it (TOTP, QR Code, OTP, Step-Up challenges).

### MED-8: No CSRF Protection for State-Changing Operations

CSRF is globally disabled (`csrf(AbstractHttpConfigurer::disable)`). While this is standard for pure API services, if the module serves any browser-based forms, this is a vulnerability.

### MED-9: Blocking WebClient Calls in BiometricServiceAdapter

All biometric service calls use `.block()` on reactive WebClient, which blocks the servlet thread. For production under load, this should use `RestClient` (Spring Boot 3.2+) or proper async handling.

---

## AUTHENTICATION ENDPOINTS INVENTORY

### Password Authentication

| Endpoint | Method | Status | Issues |
|----------|--------|--------|--------|
| `/api/v1/auth/register` | POST | WORKING | No email verification |
| `/api/v1/auth/login` | POST | WORKING | No audit logging |
| `/api/v1/auth/logout` | POST | WORKING | Token ownership not validated |
| `/api/v1/auth/refresh` | POST | WORKING | Token rotation works |
| `/api/v1/auth/me` | GET | WORKING | None |
| `/api/v1/users/{id}/change-password` | POST | WORKING | None |
| `/api/v1/auth/forgot-password` | POST | MISSING | Critical gap |
| `/api/v1/auth/reset-password` | POST | MISSING | Critical gap |
| `/api/v1/auth/verify-email` | POST | MISSING | High gap |

### Face Authentication

| Endpoint | Method | Status | Issues |
|----------|--------|--------|--------|
| `/api/v1/biometric/enroll/{userId}` | POST | WORKING | Multipart upload, anti-spoof |
| `/api/v1/biometric/verify/{userId}` | POST | WORKING | Confidence threshold 0.7 |
| Auth session FACE step | POST | WORKING | Via FaceAuthHandler with base64 |

### Fingerprint Authentication

| Endpoint | Method | Status | Issues |
|----------|--------|--------|--------|
| `/api/v1/biometric/fingerprint/enroll/{userId}` | POST | MISSING | No enrollment path |
| Auth session FINGERPRINT step | POST | WORKING | Via FingerprintAuthHandler |
| BiometricServicePort.verifyFingerprint() | - | WORKING | Adapter calls external service |
| BiometricServicePort.enrollFingerprint() | - | MISSING | Method not on port |

### Multi-Step Auth Sessions

| Endpoint | Method | Status | Issues |
|----------|--------|--------|--------|
| `/api/v1/auth/sessions` | POST | WORKING | Creates session |
| `/api/v1/auth/sessions/{id}` | GET | BROKEN | Requires JWT (CRITICAL-1) |
| `/api/v1/auth/sessions/{id}/steps/{n}` | POST | BROKEN | Requires JWT (CRITICAL-1) |
| `/api/v1/auth/sessions/{id}/steps/{n}/skip` | POST | BROKEN | Requires JWT (CRITICAL-1) |
| `/api/v1/auth/sessions/{id}/cancel` | POST | BROKEN | Requires JWT (CRITICAL-1) |

### Auth Method Handlers

| Handler | Type | Status | Notes |
|---------|------|--------|-------|
| PasswordAuthHandler | PASSWORD | PRODUCTION READY | BCrypt, user lookup |
| FaceAuthHandler | FACE | PRODUCTION READY | Base64, anti-spoof, confidence |
| FingerprintAuthHandler | FINGERPRINT | WORKING* | *No enrollment path |
| EmailOtpAuthHandler | EMAIL_OTP | PRODUCTION READY | 6-digit, 5min TTL |
| SmsOtpAuthHandler | SMS_OTP | PRODUCTION READY | Twilio integration |
| TotpAuthHandler | TOTP | PRODUCTION READY | RFC 6238, Google Auth compatible |
| QrCodeAuthHandler | QR_CODE | PRODUCTION READY | One-time token, 5min TTL |
| HardwareKeyAuthHandler | HARDWARE_KEY | MVP ONLY | No crypto verification |
| VoiceAuthHandler | VOICE | WORKING* | *No enrollment path |
| NfcDocumentAuthHandler | NFC_DOCUMENT | STUB | Always fails |

### Tenant & Flow Management

| Endpoint | Method | Status | Issues |
|----------|--------|--------|--------|
| `/api/v1/tenants` CRUD | All | WORKING | @PreAuthorize enforced |
| `/api/v1/tenants/{id}/auth-flows` CRUD | All | WORKING | @PreAuthorize enforced |
| `/api/v1/tenants/{id}/auth-methods` | GET/PUT | WORKING | @PreAuthorize enforced |
| `/api/v1/auth-methods` | GET | WORKING | Public, read-only |

### RBAC Endpoints

| Endpoint | Method | Status | Issues |
|----------|--------|--------|--------|
| `/api/v1/roles` CRUD | All | WORKING | @PreAuthorize enforced |
| `/api/v1/permissions` | GET | WORKING | @PreAuthorize enforced |
| `/api/v1/users/{id}/roles` | All | WORKING | @PreAuthorize enforced |

### Step-Up Authentication

| Endpoint | Method | Status | Issues |
|----------|--------|--------|--------|
| `/api/v1/step-up/register-device` | POST | WORKING | ECDSA P-256 |
| `/api/v1/step-up/challenge` | POST | WORKING | Nonce-based |
| `/api/v1/step-up/verify-challenge` | POST | WORKING | Signature verification |

---

## WHAT A CLIENT APPLICATION NEEDS (Gap Analysis)

### To Connect and Use This Module, a Client Needs:

| Requirement | Available? | Gap |
|-------------|-----------|-----|
| Base URL and API prefix | YES | `/api/v1/` documented |
| CORS configuration | YES | Pre-configured for localhost:3000/4200/5173 |
| OpenAPI/Swagger spec | PARTIAL | Runtime only, no exportable spec file |
| Auth flow (register + login) | YES | Working password auth |
| Token management (refresh/logout) | YES | JWT with rotation |
| Password reset | NO | Missing endpoints |
| Biometric enrollment (face) | YES | Multipart upload |
| Biometric enrollment (fingerprint) | NO | Missing entirely |
| Multi-step auth | PARTIAL | Session creation works, sub-endpoints broken |
| Tenant configuration | YES | Full CRUD |
| Auth flow customisation | YES | Per-tenant flow configuration |
| RBAC management | YES | Role/permission CRUD |
| User management | YES | Full CRUD with search |
| Error response format | YES | Consistent ErrorResponse format |
| Rate limiting | PARTIAL | Implemented but may not be applied |
| Audit trail | PARTIAL | Controller works, not wired to use cases |
| Client SDK | NO | No generated SDK |
| Webhook/event notifications | NO | EventPublisher exists but unused |
| Health/status endpoint | PARTIAL | Basic only, no dependency checks |

---

## PRODUCTION DEPLOYMENT CHECKLIST

### Infrastructure

- [x] Dockerfile (multi-stage, Java 21)
- [x] docker-compose.yml (PostgreSQL + Redis + App)
- [x] GCP deployment scripts
- [x] Environment variable configuration (.env.example)
- [x] Flyway migrations (17 versions, V0-V17)
- [ ] Kubernetes manifests
- [ ] CI/CD pipeline configuration
- [ ] Database backup strategy
- [ ] Redis persistence configuration

### Security

- [x] JWT authentication filter
- [x] BCrypt password encoding
- [x] CORS properly configured (no wildcards)
- [x] Custom exception hierarchy (17 exceptions)
- [x] Global exception handler
- [x] RBAC framework implemented
- [ ] Auth session endpoints accessible without JWT (CRITICAL-1)
- [ ] All controllers have @PreAuthorize (CRITICAL-4,5,6)
- [ ] Password reset flow (CRITICAL-3)
- [ ] Email verification flow
- [ ] Rate limiting verified and applied
- [ ] JWT secret rotation mechanism
- [ ] Swagger/H2/Actuator disabled in prod profile
- [ ] Security headers (HSTS, CSP, X-Frame-Options)

### Monitoring

- [x] Spring Actuator configured
- [x] Micrometer/Prometheus dependency
- [ ] Custom metrics (auth success/failure rates)
- [ ] Health checks for external dependencies
- [ ] Alerting rules
- [ ] Structured logging format

### Data

- [x] 17 Flyway migrations
- [x] Sample data seeded (V15)
- [x] Role/permission seed data (V3, V10)
- [ ] Data encryption at rest
- [ ] PII handling compliance (GDPR/KVKK)
- [ ] Database connection pooling configured for production

---

## RECOMMENDED FIX PRIORITY ORDER

### Week 1: Critical Blockers

1. **Fix auth session endpoints** - Add wildcard to permitAll (CRITICAL-1) - 15 min
2. **Add @PreAuthorize to UserSettingsController** (CRITICAL-4) - 30 min
3. **Add @PreAuthorize to AuditLogController** (CRITICAL-5) - 15 min
4. **Add @PreAuthorize to EnrollmentController** (CRITICAL-6) - 30 min
5. **Add fingerprint enrollment to BiometricServicePort** (CRITICAL-2) - 2 hours
6. **Add forgot/reset password endpoints** (CRITICAL-3) - 4 hours
7. **Add missing exception handlers** to GlobalExceptionHandler (HIGH-11) - 1 hour

### Week 2: High Priority

8. **Wire AuditLogAdapter into use case services** (HIGH-1) - 3 hours
9. **Delete legacy dead code** (HIGH-3) - 30 min
10. **Consolidate DTO layer** (HIGH-4) - 4 hours
11. **Restrict Swagger/H2/Actuator in prod** (HIGH-8) - 1 hour
12. **Wire EventPublisherAdapter** (HIGH-2) - 2 hours

### Week 3: Medium Priority

13. **Add email verification flow** (HIGH-10) - 4 hours
14. **Expand biometric endpoints** (MED-1) - 3 hours
15. **Add integration tests** (MED-3) - 8 hours
16. **Generate exportable OpenAPI spec** (MED-6) - 2 hours
17. **Add proper health checks** (MED-2) - 2 hours

---

## CONCLUSION

The Identity Core API has a solid architectural foundation with a well-implemented hexagonal architecture, comprehensive auth handler system supporting 10 authentication methods, and proper domain modeling. The tenant-configurable auth flow system is a powerful differentiator.

However, **7 critical blockers prevent production use**:
1. Multi-step auth sessions are broken for unauthenticated users
2. Fingerprint enrollment is completely missing
3. Password reset flow is missing
4. Three controllers lack authorization checks
5. Logout doesn't validate token ownership

The estimated effort to reach production readiness is **3-4 weeks** of focused development, with the critical blockers addressable in the first week.

---

*Report generated as part of deep audit investigation.*
*Branch: claude/audit-auth-module-w4OTU*
