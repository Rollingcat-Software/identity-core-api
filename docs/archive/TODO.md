# Identity-Core-API TODO — Backend backlog

> Source of truth for the backend sprint. Mirrors the format of `web-app/TODO.md`. Seeded from `/home/deploy/.claude/plans/rustling-pondering-wind.md` (Phase C/D/E/F/H backend items) and unfinished `CHANGELOG.md` entries.

**Current branch:** `main`
**Last updated:** 2026-04-18

---

## Open — 2026-04-18 (Phase A–H restructure)

### Phase C — Wave 0 ops hardening (CRITICAL — `.env.prod` live-cred exposure)

`.env.prod` contains live PostgreSQL / Redis / JWT / Twilio / biometric API creds and is in git history. Rotate BEFORE purge so leaked values are already dead. Schedule a 2-hour maintenance window — JWT rotation signs everyone out.

- [ ] **C1a.** Rotate `shared-postgres` `postgres` user password; roll the new password into `/etc/fivucsas/.env.prod` on the Hetzner VPS.
- [ ] **C1b.** Rotate `shared-redis` password; roll into `.env.prod`.
- [ ] **C1c.** Rotate `JWT_SECRET` — forces full MFA session invalidation, acceptable inside the announced maintenance window.
- [ ] **C1d.** Rotate Twilio Account SID + Auth Token (regenerate in Twilio console); update `TwilioConfig`.
- [ ] **C1e.** Rotate biometric-processor `X-API-Key` shared secret; update both identity-core-api + biometric-processor configs.
- [ ] **C1f.** Rotate Hostinger SMTP password.
- [ ] **C2.** Move secrets to runtime injection: GitHub Actions `secrets` → workflow env → Docker `--env-file /etc/fivucsas/.env.prod` (root:root, 0600, never in git).
- [ ] **C3.** `git filter-repo --path .env.prod --invert-paths` on `identity-core-api`; force-push after team (solo user + agents) is aligned. Update all clones.
- [ ] **C4.** Traefik tightening on `bio.fivucsas.com` — add existing `rate-limit` middleware (avg 30 r/s, burst 50) + new `admin-whitelist` (VPS IP + dev laptop + on-call). Deny everything else.
- [ ] **C5.** Enable GitHub push-protection on `Rollingcat-Software/identity-core-api`; add `gitleaks` step to `ci.yml`.

### Phase D — Security depth (backend)

- [ ] **D4.** Run the OpenID conformance-suite against `https://api.fivucsas.com/.well-known/openid-configuration`. Verify `code + id_token + PKCE S256 + JWKS reachable`. Fix any reported deviations. Target: Basic-certification-ready profile.
- [ ] **D5a.** PKCE failure audit logging — every `code_verifier` mismatch / code-reuse attempt writes to `audit_logs` with `actorIp`, `clientId`, `failureReason`. Add `AuditLogType.PKCE_FAILURE` enum value.
- [ ] **D5b.** PKCE rate-limit by `clientId` — extend `RateLimitInterceptor` (or equivalent) to throttle repeated PKCE failures per `clientId` in addition to per-IP throttling.

### Phase E — Performance (CI)

- [ ] **E3.** Add `-T 2C` (parallel threads per CPU core) to Maven invocations in `.github/workflows/ci.yml` — halves CI wall-clock.

### Phase F — Compliance & observability (server-side)

- [ ] **F2.** Backup restore verification cron — weekly job on the Hetzner VPS that unzips the latest `/opt/projects/backups/*/identity_core.sql.gz`, restores to a throwaway `identity_core_verify` DB, runs `SELECT COUNT(*) FROM users`, and alerts on mismatch vs live. Prevents "we have backups but they're corrupt" incidents.

### Phase H — Code-quality waves 2 + 3

#### H1 (Wave 2)
- [ ] Unify `LoginMfaFlow` + `MultiStepAuthFlow` (~1000 LOC de-duplication). *(Frontend-driven; backend DTOs must support either caller identically.)*
- [ ] **DTO migration** — replace 135 `Map.of()` response bodies across controllers with typed DTOs (`record`-based). Prioritize `OAuth2Controller`, `AuthController`, `TenantController`, `RoleController`, `AdminOverviewController`.
- [ ] **Admin `@PreAuthorize` sweep** — add `@PreAuthorize("@rbac.isTenantAdmin()")` on `TenantController`, `RoleController`, `AdminOverviewController`, any admin `POST/PUT/DELETE` missing it.
- [ ] Unified `ErrorResponse` DTO across OAuth + Auth controllers (one shape, one mapper, one Swagger schema).

#### H2 (Wave 3)
- [ ] `@WebMvcTest` coverage for the 17 controllers that only have integration tests today — adds fast-feedback slice tests per controller.
- [ ] `@Version` optimistic locking on `User`, `AuthFlow`, `Tenant` entities.
- [ ] JPA cascade refactor — replace `CascadeType.ALL` with explicit `{PERSIST, MERGE}` on relationship mappings; move deletion to service layer.
- [ ] `AuthFlowStep.alternativeMethods` — `FetchType.EAGER` → `LAZY`.
- [ ] `@Transactional(readOnly=true)` sweep on 50+ query services (read-only hint cuts Hibernate flush overhead).

---

## Completed — 2026-04-18 (backend)

- [x] **Flyway V38** — flipped `fivucsas-web-dashboard` OAuth2 client to public + PKCE-only (commit `86e3c6d`) — SPA cannot hold a secret.
- [x] **Flyway V37** — reaffirmed `oauth2_clients.tenant_id` index (commit `06a9f78`) — audit seq-scan concern was stale; V24 already had it.
- [x] **`marmara-bys-demo` OAuth2 client** registered for `demo.fivucsas.com` hosted-login flow.
- [x] **CI split** — `ci.yml` split into unit + integration with `RUN_INTEGRATION` env-gated integration stage (commit `4a0f58f`).
- [x] **GDPR Art. 17 / 20** — `GET /users/{id}/export` + `SoftDeletePurgeJob` + `PurgeAdminController` shipped 2026-04-16b.

---

## Reference

- Backend CHANGELOG: `CHANGELOG.md`
- Architecture: `ROADMAP.md`
- Full cross-repo plan: `/home/deploy/.claude/plans/rustling-pondering-wind.md`
- Parent repo roadmap: `../ROADMAP.md`
- Web-app TODO (mirror): `../web-app/TODO.md`
