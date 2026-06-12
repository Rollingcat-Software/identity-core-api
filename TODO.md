# Identity-Core-API TODO — Active backlog

> Active, near-term backend backlog. Historical / phase-restructure items live in
> `docs/archive/TODO.md` (the 49-item 2026-04-18 integration audit). Mirrors the
> checkbox format of `web-app/TODO.md`.

**Current branch:** `main`
**Last updated:** 2026-06-12

---

## Resolved — 2026-06-12

### [P0 — CI HEALTH] Restore the Testcontainers integration test lane ✅ DONE (PR #221)

- [x] **Restored the Testcontainers integration test lane (required check on `main`).**
  `Integration tests (Testcontainers)` is GREEN: **94 run / 0 fail / 0 error / 0 skip**.
  The red was NOT environmental — it was test-only staleness + a latent CI-guard bug,
  fixed in PR #221 (#220 first cut errors 29→5 with the Instant→Timestamp fixture fix):
  - `CrossTenantIsolationIT.superAdminNoHeader_crossTenant` (×6): STALE expectation. The
    suite (PR #132) predates PR #134, which added the Hibernate `@Filter(tenantFilter)` to
    these six entities. Post-#134 a header-less ROOT scopes to its HOME tenant (the
    documented #134 behaviour change), so it no longer auto-sees all tenants. Updated the
    test to assert the current contract + prove true cross-tenant via the explicit
    `TenantFilterBypass`. **Not a product bug** — the production isolation is correct.
  - `AuthenticationFlowIntegrationTest` (5) + `UserApiIntegrationTest` register 422s:
    `EmailDomainNotAllowed`. The ITs self-register `@fivucsas.com` with no tenant context;
    pointed `app.default-tenant-slug` at a test-only `default` catch-all tenant
    (`db/test-fixtures/V86_5__…`, single-step PASSWORD flow → mints tokens). Test-config
    only; production validation unchanged.
  - `UserApiIntegrationTest` 429 cascade: shared-IP rate-limiter; reset the per-IP
    REGISTRATION/LOGIN buckets `@BeforeEach`. Test-only.
  - Stale status expectations: register is 201 Created (not 200); logout is an
    authenticated endpoint returning 204 (not anon 200). Updated assertions.
  - CI guard `Assert tenant-isolation ITs actually executed`: summed JUnit `@Nested`
    surefire shards (CrossTenantIsolationIT writes per-nested-class reports; the parent
    report reads `tests=0`).
  - **`--admin` is no longer needed for api merges** — both required checks
    (`Maven test (unit)` + `Integration tests (Testcontainers)`) are green.

## Open — 2026-06-07

### Deferred follow-ups from #211 (authz hardening)

- [ ] **Postgres `FORCE ROW LEVEL SECURITY` + non-superuser DB role.** Defense-in-depth
  beyond the Hibernate `@Filter(tenantFilter)` so a PK-by-id query (or any raw access)
  cannot bypass tenant isolation. **Infra task** — the production DB currently connects
  as a shared superuser across ~6 apps, which RLS does not constrain; needs a dedicated
  non-superuser role before `FORCE ROW LEVEL SECURITY` can be enabled meaningfully.
- [ ] **Generic target-aware `RbacPermissionEvaluator`.** `hasPermission(#id, …)` SpEL
  currently IGNORES the supplied target id (it only checks that the caller holds the
  permission, not that the target is in-scope). The #211 IDOR fixes added per-endpoint
  scope assertions as a workaround; the durable fix is to make the evaluator honor the
  `#id` target generically so future endpoints get object-level checks for free.

---

## Reference

- Archived integration audit (49 items): `docs/archive/TODO.md`
- Roadmap: `ROADMAP.md` (this repo) + parent `ROADMAP_MASTER.md`
- Changelog: `CHANGELOG.md`
