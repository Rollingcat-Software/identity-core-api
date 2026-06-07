# Identity Core API — Roadmap

> **Historical snapshot below (2026-03-15) — superseded by parent ROADMAP.md.**
> Most items listed there as "remaining" have since shipped. For current status,
> see the parent repo's ROADMAP_MASTER.md and this repo's CHANGELOG.md.
> The **Near-term** section immediately below reflects the live 2026-06-07 priorities.

## Near-term (2026-06-07)

1. **[P0] Restore the Testcontainers integration CI lane.** The
   `Integration tests (Testcontainers)` job is one of the two required checks on
   `main` and is broadly red (`AuthenticationFlowIntegrationTest`,
   `UserApiIntegrationTest`, `CrossTenantIsolationIT`). Failure is
   pre-existing/environmental (test-DB / biometric-processor / migration setup),
   not the application logic of #209/#210/#211. Until restored, the integration
   safety-net is down and merges rely on admin-override. See `TODO.md` [P0].
2. **RLS enforcement (infra).** Add Postgres `FORCE ROW LEVEL SECURITY` behind a
   dedicated non-superuser DB role (today's connection is a shared superuser across
   ~6 apps, which RLS does not constrain) — defense-in-depth under the Hibernate
   `@Filter(tenantFilter)`.
3. **`RbacPermissionEvaluator` hardening.** Make `hasPermission(#id, …)` honor the
   target id generically so object-level (IDOR) checks are automatic, replacing the
   per-endpoint scope assertions added in #211.

---

## Historical snapshot

> Last updated: 2026-03-15

## Deployment Status

**Deployed at:** https://api.fivucsas.com
**Stack:** Java 21 / Spring Boot 3.2
**Server:** Hetzner VPS (Docker + Traefik + Let's Encrypt)
**Health:** UP (biometric service UNKNOWN — not yet deployed)

### What's Working

- [x] Spring Boot API deployed and serving HTTPS
- [x] PostgreSQL database connected
- [x] Health endpoint at `/actuator/health`
- [x] Spring Security configured (root `/` returns 403 by design)

### Deployment Remaining

- [ ] Deploy biometric-processor microservice
- [ ] Enable real email OTP delivery (replace mock sender)
- [ ] Enable real SMS OTP delivery
- [ ] Connect web-app frontend to auth API
- [ ] Sentry error tracking
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Automated database backups

### Known Behaviors

- `api.fivucsas.com/` returns 403 — Spring Security blocks unauthenticated root. Use `/actuator/health`.
- Biometric health shows UNKNOWN until biometric-processor is deployed. Does not affect overall UP status.
- `favicon.ico` requests return 401/403 — APIs don't serve favicons.

---

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
