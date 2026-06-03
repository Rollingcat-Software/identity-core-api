# SSO App Launcher — Phase 1 Implementation Plan (SSO session + silent authorize)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. **Write the failing test first against the REAL classes** (this plan gives exact paths + interfaces + the behavior each test must assert; write the concrete JUnit/MockMvc body against the actual signatures at execution time — do not copy fabricated assertions).

**Goal:** Let a user who completed one full FIVUCSAS login launch additional registered apps with a *silent* `/oauth2/authorize` (no re-login), via an SSO session — feature-flagged OFF by default.

**Architecture:** Spring Security here is `SessionCreationPolicy.STATELESS`, so the SSO "session" is an **opaque random token in an HttpOnly cookie, backed by Redis** (not an `HttpSession`). It is minted at `POST /oauth2/authorize/complete` (first full login). A new filter scoped to the authorize endpoint resolves that cookie into a `SecurityContext` `Authentication`, so the **already-existing** "authenticated → mint code" branch in `OAuth2Controller.authorize` (currently only reachable with a Bearer JWT) fires for the browser's top-level redirect too. `prompt`, `max_age`, and a per-client re-auth policy gate when silent is allowed. The whole path is behind `app.auth.sso-session` (default `false` ⇒ today's behavior exactly).

**Tech Stack:** Java 21, Spring Boot 3.4.7, Spring Security (STATELESS), Redis (already in stack, used by rate-limiting), Flyway, JUnit 5 + MockMvc (+ Testcontainers for the integration gate).

**Scope:** This is **Phase 1 of 5** (see `SSO_APP_LAUNCHER_DESIGN.md`). Phases 2–5 (launcher metadata + `/launcher/apps` API, web launcher home, mobile "My Apps", hardening/SLO) get their own plans after this lands. This phase produces working, testable software on its own: a second app launches silently within the session window.

---

## File structure

**Create:**
- `domain/model/SsoSession.java` — immutable record: `sessionId`, `identityId`, `userId`, `tenantId`, `authTimeEpoch`, `amr` (List<String>), `acr`, `createdEpoch`, `maxAgeSeconds`.
- `application/port/output/SsoSessionStorePort.java` — `create(SsoSession)`, `find(String sessionId): Optional<SsoSession>`, `revoke(String sessionId)`, `revokeAllForIdentity(UUID)`.
- `infrastructure/adapter/RedisSsoSessionStore.java` — Redis-backed adapter (key `sso:session:{id}`, TTL = maxAge), reusing the existing `RedisTemplate`/`StringRedisTemplate` bean used by rate-limiting.
- `infrastructure/oauth2/SsoSessionCookie.java` — cookie read/write helper: name `fv_sso`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/api/v1/oauth2`, max-age = session window; opaque 256-bit random id (the id is the only thing in the cookie; all state is server-side in Redis).
- `infrastructure/oauth2/SsoSessionAuthenticationFilter.java` — `OncePerRequestFilter`, registered ONLY for `/api/v1/oauth2/authorize`; if the flag is on and `fv_sso` resolves to a live `SsoSession`, set a `UsernamePasswordAuthenticationToken` (principal = the session's `userId`/subject the existing mint path expects) into the `SecurityContext`. No-op when flag off / cookie absent / session missing or expired.
- `application/service/SsoSessionService.java` — orchestrates: `establish(...)` (build + store + return cookie value), `resolve(cookieValue)`, `satisfiesPolicy(session, client, prompt, maxAge)`, `revoke(...)`.

**Modify:**
- `controller/OAuth2Controller.java` — (a) at the end of a successful `POST /authorize/complete`, when flag on, call `SsoSessionService.establish(...)` and attach the `Set-Cookie`; (b) in `GET /authorize`, handle `prompt`/`max_age` and the per-client re-auth policy (the "authenticated → mint code" branch already exists at ~L136-162; gate it through `satisfiesPolicy`).
- `config/SecurityConfig.java` — register `SsoSessionAuthenticationFilter` before the JWT filter for the authorize matcher only; keep global policy STATELESS (the filter sets a request-scoped Authentication, it does NOT create an HttpSession).
- `entity/OAuth2Client.java` + new Flyway `V83__oauth2_clients_reauth_policy.sql` — add `reauth_policy VARCHAR(16) NOT NULL DEFAULT 'silent'` (`silent` | `step_up` | `always`). (Launcher-visibility/logo columns are Phase 2 — not here.)
- `application/service/LogoutService` (or wherever `POST /auth/logout` lives) — revoke the SSO session + expire the cookie.
- `src/main/resources/application*.yml` — `app.auth.sso-session.enabled: false`, `app.auth.sso-session.max-age: PT8H`.

---

## Tasks

### Task 1: SSO session model + Redis store
**Files:** Create `SsoSession.java`, `SsoSessionStorePort.java`, `RedisSsoSessionStore.java`; Test `src/test/java/.../infrastructure/adapter/RedisSsoSessionStoreTest.java`.

- [ ] **Step 1 — failing test.** Assert: `create()` then `find(id)` returns an equal `SsoSession`; `find` of an unknown id is empty; `revoke(id)` then `find` is empty; the Redis key is written with a TTL equal to `maxAgeSeconds` (assert via the test Redis / Testcontainers `getExpire`). Use the project's existing Redis test pattern (grep `RedisTemplate` test usages; reuse the Testcontainers Redis from the integration gate).
- [ ] **Step 2 — run it, confirm it fails** (types not defined).
- [ ] **Step 3 — implement** the record + port + adapter (serialize `SsoSession` to a Redis hash or JSON string; key `sso:session:{id}`; `opsForValue().set(key, json, Duration.ofSeconds(maxAge))`).
- [ ] **Step 4 — run, confirm pass.**
- [ ] **Step 5 — commit** `feat(sso): SsoSession model + Redis-backed store (flagged feature, unused yet)`.

### Task 2: Cookie helper
**Files:** Create `SsoSessionCookie.java`; Test `SsoSessionCookieTest.java`.

- [ ] **Step 1 — failing test.** `build(value, maxAge)` produces a `ResponseCookie` with `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/api/v1/oauth2`, the given max-age; `expire()` produces a max-age=0 cookie; `read(HttpServletRequest)` returns the `fv_sso` value or empty.
- [ ] **Step 2 — fails.** **Step 3 — implement** with Spring `ResponseCookie`. **Step 4 — pass.** **Step 5 — commit** `feat(sso): fv_sso cookie helper`.

### Task 3: SsoSessionService (establish / resolve / policy)
**Files:** Create `SsoSessionService.java`; Test `SsoSessionServiceTest.java`.

- [ ] **Step 1 — failing tests** (one behavior each):
  - `establish(...)` stores a session (verify via the store port mock) and returns a cookie value whose id matches the stored session.
  - `resolve(cookieValue)` returns the live session; returns empty for an unknown/expired id.
  - `satisfiesPolicy(session, client, prompt=null, maxAge=null)`: TRUE when client `reauth_policy=silent` and `now - authTime < window`; FALSE when policy=`always`; FALSE when policy=`step_up` (caller must step-up); FALSE when `prompt=login`; FALSE when `now - authTime > maxAge`.
- [ ] **Step 2 — fail. Step 3 — implement** (pure logic over the port + a `Clock` injected for testability — pass timestamps in, do not call wall-clock in the policy method directly so tests are deterministic). **Step 4 — pass. Step 5 — commit** `feat(sso): SsoSessionService + silent-launch policy`.

### Task 4: Establish the session at /authorize/complete (flag-gated)
**Files:** Modify `OAuth2Controller.java` (the `POST /authorize/complete` success path, ~L199-248); Test `OAuth2AuthorizeCompleteSsoTest.java` (MockMvc).

- [ ] **Step 1 — failing test.** With flag ON, a successful `/authorize/complete` response carries a `Set-Cookie: fv_sso=…; HttpOnly; Secure; SameSite=Lax` and a session row exists in the store for the authenticated user. With flag OFF, **no** `Set-Cookie` (assert absent) — proves default behavior unchanged.
- [ ] **Step 2 — fail. Step 3 — implement**: after the code is minted, if `ssoSessionProps.enabled`, call `ssoSessionService.establish(identity, userId, tenantId, amr, acr)` and add the cookie to the response. **Step 4 — pass. Step 5 — commit** `feat(sso): mint SSO session on first login (flagged)`.

### Task 5: Resolve the cookie on GET /authorize (the silent path)
**Files:** Create `SsoSessionAuthenticationFilter.java`; Modify `SecurityConfig.java`; Test `SsoSessionAuthorizeFilterTest.java` + extend the authorize MockMvc test.

- [ ] **Step 1 — failing test.** With flag ON and a valid `fv_sso` cookie (no Bearer header), `GET /api/v1/oauth2/authorize?client_id=…&redirect_uri=…&response_type=code&code_challenge=…` returns `200` with a `code` (the existing authenticated-branch mint). Without the cookie → the existing `action:authenticate` response (unchanged). Forged/expired cookie → treated as unauthenticated (no mint). With flag OFF → cookie ignored entirely.
- [ ] **Step 2 — fail. Step 3 — implement** the `OncePerRequestFilter` (resolve cookie → `SsoSessionService.resolve` → on hit set `SecurityContextHolder` Authentication with the same principal shape the existing mint branch reads via `authentication.getName()`); register it in `SecurityConfig` `addFilterBefore(...)` scoped to the authorize matcher; keep STATELESS. **Step 4 — pass. Step 5 — commit** `feat(sso): resolve SSO cookie → silent authorize mint (flagged)`.

### Task 6: prompt / max_age / per-client reauth_policy gating
**Files:** Modify `OAuth2Controller.authorize` (add `prompt`, `max_age` params); `entity/OAuth2Client.java` + `V83__oauth2_clients_reauth_policy.sql`; Test `OAuth2SilentPolicyTest.java`.

- [ ] **Step 1 — failing tests.** `prompt=none` + no usable session → RFC `login_required` error (not the widget `action` blob). `prompt=login` → never silent (forces hosted login even with a live session). client `reauth_policy=step_up` → not silent (returns a step-up-required signal). `max_age` exceeded → not silent. `reauth_policy=silent` within window → mints. (Gate the existing mint branch through `ssoSessionService.satisfiesPolicy(...)`.)
- [ ] **Step 2 — fail. Step 3 — implement** the migration (additive, default `'silent'`), entity field, and the param + policy gate. **Step 4 — pass. Step 5 — commit** `feat(sso): prompt/max_age + per-client reauth_policy gating + V83`.

### Task 7: Logout revokes the SSO session
**Files:** Modify the `POST /auth/logout` handler/service; Test extends the logout test.

- [ ] **Step 1 — failing test.** With flag ON, after logout the `fv_sso` session is revoked in the store and the response expires the cookie (max-age 0). **Step 2 — fail. Step 3 — implement.** **Step 4 — pass. Step 5 — commit** `feat(sso): logout revokes SSO session + expires cookie`.

### Task 8: Integration test — the end-to-end silent second launch
**Files:** `src/test/java/.../OAuth2SsoLaunchIntegrationTest.java` (Testcontainers: Postgres + Redis).

- [ ] **Step 1 — failing test.** Full flow with flag ON: (1) complete login for app A via `/authorize/complete` → capture `fv_sso`; (2) `GET /authorize` for app B (`marmara-bys-demo`-like, `reauth_policy=silent`) **with only the cookie** → `200` + `code`; (3) exchange B's code at `/token` → valid tokens whose `sub` is **pairwise for B** and `tenant_id` is the user's real tenant (assert isolation preserved). Then flip flag OFF and assert step (2) returns `action:authenticate` (no silent mint).
- [ ] **Step 2 — fail (or wire) → Step 3 — make green → Step 4 — pass → Step 5 — commit** `test(sso): end-to-end silent second-app launch + isolation + flag-off parity`.

### Task 9: Flag wiring + docs
**Files:** `application*.yml` (`app.auth.sso-session.enabled: false`, `.max-age: PT8H`); a `@ConfigurationProperties` `SsoSessionProperties`; update `SSO_APP_LAUNCHER_DESIGN.md` "Phase 1: done" + the api `CLAUDE.md` operator note (how to enable + the canary plan).

- [ ] **Step 1** add the properties class + yml (default OFF). **Step 2** `./mvnw -T 2C test` green. **Step 3 — commit** `chore(sso): config properties + docs (default OFF)`.

---

## Security acceptance criteria (must all hold before any canary)
- Flag OFF ⇒ byte-for-byte today's behavior (no cookie minted, cookie ignored on authorize). Proven by Tasks 4 & 8.
- Forged/tampered/expired cookie never mints a code (Task 5).
- A tenant whose policy mandates step-up is never silently bypassed (Task 6).
- Minted tokens keep pairwise `sub` + the user's real `tenant_id` (Task 8).
- Every silent mint is audited (who/app/sessionId/acr) — extend `AuditEventPublisher`.
- `prompt=none` with no usable session returns `login_required` (RFC-correct), not a silent mint and not a UI.

## Rollout (per the "reversible risky changes" rule)
Dark (flag off, code shipped) → enable in staging → canary ONE tenant (Marmara) end-to-end (`app.fivucsas` → BYS demo) → broad. Kill switch = the flag (no redeploy).

## Self-review notes
- Spec coverage: implements §3 (SSO session + silent authorize) and §6 (security model) of the design; §4 launcher metadata beyond `reauth_policy`, the `/launcher/apps` API, and all UI are explicitly **out of scope** (Phases 2–4).
- The exact principal shape the filter must set is whatever `OAuth2Controller.authorize`'s authenticated branch reads (`authentication.getName()` + the tenant/PKCE checks in `validateAuthorizeRequest`) — confirm against the real method when writing Task 5's test.
- `OAuth2Client` migration is additive + default-safe (`'silent'`), consistent with the V82 cross_tenant precedent.
