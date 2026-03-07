# Identity Core API - Integration Audit & TODO

> Cross-module integration audit completed March 2026.
> Compares identity-core-api against web-app frontend and biometric-processor.

---

## Previous Audits Summary

Previous audit (Feb 2026, AUDIT_REPORT.md) identified:
- 3 critical issues (WebAuthn crypto, NFC stub, logout token ownership)
- 10 high-priority gaps
- 8 medium improvements
- Overall readiness: 74/100

---

## NEW: Cross-Module Integration Issues

### CRITICAL - Breaking frontend integration

- [x] **XC1** UserController.getAllUsers() already returns paginated format (content, totalElements, totalPages, page, size) via in-memory pagination. Frontend UserRepository handles both formats. **RESOLVED**.
- [x] **XC2** `UserController` maps `UserResponse` to legacy `UserDto` via `mapToUserDto()`, adding an unnecessary translation layer. The `UserDto` class (legacy package) duplicates `UserResponse` fields. **RESOLVED**: Deleted `UserDto`, controllers now return `UserResponse` directly. Added `lastLoginAt`/`lastLoginIp` fields to `UserResponse`. `AuthResponse` updated to use `UserResponse`.
- [x] **XC3** TenantController.getAllTenants() already returns paginated format via in-memory pagination. **RESOLVED**.
- [x] **XC4** EnrollmentController.retryEnrollment() validates only FAILED enrollments can be retried, resets to PENDING, and saves. **RESOLVED**.
- [x] **XC5** EnrollmentDto includes all frontend-expected fields (authMethodType, faceImageUrl, qualityScore, livenessScore, errorCode, errorMessage). EnrollmentQueryService updated to use UserEnrollment entity. **RESOLVED**.

### HIGH - Frontend features that need backend support

- [ ] **XH1** **httpOnly Cookie Token Storage** (web-app L10) - Frontend currently stores JWT in localStorage. Backend should support `Set-Cookie` with `HttpOnly; Secure; SameSite=Strict` flags. **Add**: Cookie-based auth option in `AuthController`.
- [x] **XH2** **Paginated User List** - UserController already accepts page/size params and returns paginated format. **RESOLVED**.
- [x] **XH3** **Paginated Tenant List** - TenantController already accepts page/size params and returns paginated format. **RESOLVED**.
- [ ] **XH4** **Statistics Export** - Backend has `GET /api/v1/statistics/export?format=` endpoint (documented in IMPLEMENTATION_PLAN) but frontend doesn't use it. Verify endpoint actually works and returns CSV/PDF.
- [ ] **XH5** **Auth Methods from DB** - Frontend hardcodes auth methods. Backend `AuthMethodController` returns them from DB. Frontend should call this endpoint instead. Ensure `AuthMethodResponse` format is compatible.
- [ ] **XH6** **Guest Management API** - Backend `GuestController` is fully implemented but frontend has no guest UI. Ensure guest API is well-documented for frontend integration.
- [ ] **XH7** **TOTP Setup API** - Backend `TotpController` has setup/verify/disable/status. Frontend `TotpEnrollment.tsx` exists but isn't connected. Ensure API contract documentation is clear.
- [ ] **XH8** **Change Password API** - Backend `POST /api/v1/users/{id}/change-password` exists with password history validation. Needs frontend integration (Settings page).
- [x] **XH9** **Email Verification Flow** (from AUDIT_REPORT) - `POST /api/v1/auth/verify-email`, `POST /api/v1/auth/send-email-verification`, `POST /api/v1/auth/forgot-password`, `POST /api/v1/auth/reset-password` endpoints now exist. **RESOLVED**.

### MEDIUM - API consistency and documentation

- [ ] **XM1** **AuditLog Action Types** - Backend can produce many action types beyond what frontend filters show. Document all possible action types or add `GET /api/v1/audit-logs/action-types` endpoint.
- [ ] **XM2** **Dual DTO Layer** - `AuthController` uses legacy DTOs (`RegisterRequest`, `LoginRequest`, `AuthResponse`) while other controllers use hexagonal DTOs. Frontend must handle both. **Fix**: Consolidate to one layer.
- [ ] **XM3** **OpenAPI Spec Export** - No exportable OpenAPI spec (only runtime Swagger UI). Frontend needs reliable API documentation. **Fix**: Configure SpringDoc to export `openapi.json` at build time.
- [ ] **XM4** **Error Code Catalog** - `ErrorResponse` has error codes but no documented catalog for frontend to map to user-facing messages. **Fix**: Create error code documentation.
- [ ] **XM5** **Tenant Status Enum** - Backend `TenantEntity` has status as String but frontend expects `ACTIVE | TRIAL | SUSPENDED | INACTIVE | PENDING`. Ensure backend returns these exact values.
- [ ] **XM6** **CORS Configuration** - Hardcoded development origins in `SecurityConfig`. Document required CORS setup for production deployment.
- [x] **XM7** **Device Response Mismatch** - Backend DeviceResponse uses @JsonProperty annotations to serialize as fingerprint, lastUsed, createdAt. **RESOLVED**.

### LOW - Architecture and cleanup

- [x] **XL1** Delete 4 legacy dead code files: `service/AuthService.java`, `service/UserService.java`, `service/BiometricService.java`, `service/StatisticsService.java`. **RESOLVED**.
- [ ] **XL2** Extract `RefreshTokenService` as port/adapter (HIGH-4 from previous audit).
- [ ] **XL3** Wire `EventPublisherPort` into services (HIGH-1 from previous audit).
- [ ] **XL4** Restrict Swagger/H2/Actuator in prod profile (HIGH-5 from previous audit).
- [x] **XL5** Fix `RegisterUserService` tenant assignment from `TenantContext` instead of hardcoding "test-tenant" (HIGH-10 from previous audit). **RESOLVED**: Uses `TenantContext.getCurrentTenant()` with configurable `app.default-tenant-slug` fallback.
- [x] **XL6** Add token ownership validation in logout (CRITICAL-3 from previous audit). **RESOLVED**: `LogoutUserService` validates token's `userId` matches authenticated user before revoking.
- [ ] **XL7** Replace blocking `WebClient.block()` calls in `BiometricServiceAdapter` with `RestClient`.

### Remaining from Previous Audit (not yet fixed)

- [ ] CRITICAL-1: WebAuthn cryptographic verification (needs Yubico library)
- [ ] CRITICAL-2: NFC Document auth always fails (prevent as required step)
- [x] CRITICAL-3: Logout doesn't validate token ownership **RESOLVED**
- [ ] HIGH-1: EventPublisherPort not wired
- [x] HIGH-2: Delete legacy dead code **RESOLVED**
- [x] HIGH-3: Consolidate dual DTO layer **RESOLVED** (UserDto eliminated)
- [ ] HIGH-4: RefreshTokenService not abstracted as port
- [ ] HIGH-5: Swagger/H2/Actuator accessible in prod
- [x] HIGH-6: No email verification flow **RESOLVED** (send-email-verification, verify-email, send-phone-verification, verify-phone endpoints added)
- [ ] HIGH-7: EnrollmentController bypasses hexagonal architecture
- [ ] HIGH-8: Blocking WebClient calls
- [ ] HIGH-9: No exportable OpenAPI spec
- [x] HIGH-10: RegisterUserService hardcodes default tenant **RESOLVED**

---

## Biometric Processor Integration Points

The identity-core-api communicates with biometric-processor via `BiometricServiceAdapter`:

| identity-core-api Call | biometric-processor Endpoint | Status |
|------------------------|------------------------------|--------|
| `enrollFace()` | `POST /api/v1/enroll` | Working |
| `verifyFace()` | `POST /api/v1/verify` | Working |
| `enrollFingerprint()` | `POST /api/v1/fingerprint/enroll` | Stub (returns structured error) |
| `enrollVoice()` | `POST /api/v1/voice/enroll` | Stub (returns structured error) |
| `verifyFingerprint()` | `POST /api/v1/fingerprint/verify` | Stub (returns structured error) |
| `verifyVoice()` | `POST /api/v1/voice/verify` | Stub (returns structured error) |

**Note**: biometric-processor only handles face biometrics. Fingerprint, voice, and other biometric types need separate infrastructure or the `BiometricServiceAdapter` needs to handle these differently (possibly stub/simulate for MVP).

---

## AUTH METHOD INTEGRATION GAPS (March 2026)

### Auth Handler Status Matrix

| Auth Method | Handler | BiometricServicePort | biometric-processor | Runtime Status |
|---|---|---|---|---|
| PASSWORD | PasswordAuthHandler | N/A | N/A | Working |
| EMAIL_OTP | EmailOtpAuthHandler | N/A | N/A | Working |
| SMS_OTP | SmsOtpAuthHandler | N/A | N/A | Working |
| TOTP | TotpAuthHandler | N/A | N/A | Working |
| QR_CODE | QrCodeAuthHandler | N/A | N/A | Working |
| FACE | FaceAuthHandler | enrollFace/verifyFace | Full implementation | Working |
| FINGERPRINT | FingerprintAuthHandler | verifyFingerprint | **STUB (always fails)** | **BROKEN** |
| VOICE | VoiceAuthHandler | verifyVoice | **STUB (always fails)** | **BROKEN** |
| NFC_DOCUMENT | NfcDocumentAuthHandler | N/A (hardcoded fail) | N/A | **BROKEN - always fails** |
| HARDWARE_KEY | HardwareKeyAuthHandler | N/A (WebAuthn) | N/A | Working (needs enrollment UI) |

### Auth Integration TODOs

- [ ] **AUTH-1** NfcDocumentAuthHandler always returns failure - should either implement or prevent as required step
- [ ] **AUTH-2** FingerprintAuthHandler calls biometric-processor stub - always fails at runtime
- [ ] **AUTH-3** VoiceAuthHandler calls biometric-processor stub - always fails at runtime
- [ ] **AUTH-4** WebAuthnController has registration endpoints but web-app has no enrollment UI
- [ ] **AUTH-5** TotpController setup/verify/disable/status endpoints not connected to frontend TotpEnrollment
- [ ] **AUTH-6** QrCodeController generate/invalidate endpoints not connected to QrCodeStep
- [ ] **AUTH-7** EnrollmentManagementController per-user endpoints not used by frontend
- [ ] **AUTH-8** BiometricServicePort.enrollFingerprint/enrollVoice call stubs in biometric-processor

---

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| Critical | 5 | Breaking frontend contracts (pagination, DTOs) |
| High | 9 | Missing endpoints, features frontend needs |
| Medium | 7 | API consistency, documentation |
| Low | 7 | Architecture cleanup, previous audit items |
| Auth | 8 | Auth method integration gaps |
| Previous | 13 | Unresolved items from Feb 2026 audit |
| **Total** | **49** | |

### Priority Order

**Week 1**: XC1-XC5 (fix breaking frontend contracts), XL6 (logout security), AUTH-1 (NFC stub)
**Week 2**: XH1-XH9 (backend support for frontend features), AUTH-4-7 (auth endpoint connections)
**Week 3**: XM1-XM7 (API consistency), XL1-XL5 (cleanup), AUTH-2-3,8 (biometric stubs)
**Week 4**: Previous audit critical + high items
