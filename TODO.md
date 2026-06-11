# Identity-Core-API TODO — Active backlog

> Active, near-term backend backlog. Historical / phase-restructure items live in
> `docs/archive/TODO.md` (the 49-item 2026-04-18 integration audit). Mirrors the
> checkbox format of `web-app/TODO.md`.

**Current branch:** `main`
**Last updated:** 2026-06-07

---

## Open — 2026-06-07

### [P0 — CI HEALTH] Restore the Testcontainers integration test lane (required check on main)

- [ ] **Restore the Testcontainers integration test lane (required check on `main`).**
  Failing broadly in CI: `AuthenticationFlowIntegrationTest`, `UserApiIntegrationTest`,
  `CrossTenantIsolationIT`. Pre-existing/environmental; investigate
  test-DB/biometric-processor/migration setup. Until fixed, the integration safety-net
  is down and merges need `--admin`.
  - It is ONE of the two required status checks on `main`
    (`Maven test (unit)` — currently green — and `Integration tests (Testcontainers)`).
  - Failure predates PRs #209/#210/#211 (likely environmental: Testcontainers setup,
    the biometric-processor `:8001` dependency, Redis `:6379`, or a migration), NOT the
    application logic of those PRs.
  - `enforce_admins=false` on `main`, so an admin-merge can override the red gate; this
    is the current norm and must be treated as a temporary exception, not a clean state.

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
