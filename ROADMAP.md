# Identity Core API - Roadmap

## Auth Method Integration Roadmap

### Phase 1: Fix Broken Auth Methods (Priority: Critical)

- [ ] Fix NfcDocumentAuthHandler to return proper "unsupported" error instead of silent failure
- [ ] Coordinate with biometric-processor to fix fingerprint/voice stubs
- [ ] Add WebAuthn enrollment endpoint documentation for frontend integration
- [ ] Fix UserController pagination (return Page<T> instead of List)
- [ ] Fix EnrollmentController retry stub

### Phase 2: Connect Frontend Features (Priority: High)

- [ ] Document TotpController API contract for frontend TotpEnrollment connection
- [ ] Document QrCodeController API contract for frontend QrCodeStep connection
- [ ] Expose EnrollmentManagementController per-user endpoints to frontend
- [ ] Add auth-methods endpoint consumption docs for frontend
- [ ] Implement Forgot/Reset Password flow end-to-end
- [ ] Add Change Password endpoint integration with frontend Settings page

### Phase 3: API Consistency (Priority: Medium)

- [ ] Consolidate dual DTO layer (legacy vs hexagonal)
- [ ] Align response field names with frontend expectations (DeviceResponse, EnrollmentResponse)
- [ ] Export OpenAPI spec at build time
- [ ] Create error code catalog for frontend
- [ ] Add audit log action types endpoint

### Phase 4: Architecture Cleanup (Priority: Low)

- [ ] Delete legacy dead code (4 files)
- [ ] Wire EventPublisherPort into services
- [ ] Replace blocking WebClient.block() with RestClient
- [ ] Restrict Swagger/H2/Actuator in production profile
- [ ] Add token ownership validation in logout
