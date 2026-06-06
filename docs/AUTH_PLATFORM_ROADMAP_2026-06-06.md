# FIVUCSAS as the Identity Provider — Auth-Platform Hardening & App-Integration Roadmap

> **Date:** 2026-06-06
> **Evidence base:** a source-verified deep-study of FIVUCSAS configurability (37 tool reads on `identity-core-api` @ HEAD `6bf5d52`) cross-referenced with the Muhabbet & Sarnıç production-readiness V&V. Every claim cites file:line / endpoint / migration.
> **Scope:** this is the *ecosystem auth* roadmap — it spans `identity-core-api` (the IdP), `web-app` (SDK/widget), infra (reachability), and the client apps (Muhabbet, Sarnıç). Most actionable code lives in `identity-core-api`, hence its home here.

---

## 1. Target architecture

**FIVUCSAS is the single Identity Provider (IdP) for the Rollingcat app suite. Every other app is an OIDC relying party (RP) / client.**

Principles:
- **No app hardcodes a login method.** An app's login screen is a FIVUCSAS *tenant auth-flow*, configured by an admin and changeable **without an app redeploy** (the config-driven login engine already does this — `ConfigDrivenLoginPolicy.java:49-68`, `LoginConfigService.getLoginConfig` 97-137). Muhabbet → SMS_OTP-anchored; Sarnıç → PASSWORD + a second factor; a future app → whatever its tenant flow says.
- **Auth is built once, in FIVUCSAS.** Apps stop re-implementing OTP, password hashing, lockout, refresh rotation, MFA. They redirect to FIVUCSAS, get an RS256 token, validate it offline via JWKS.
- **Each app keeps a thin native fallback** only for graceful degradation when FIVUCSAS is unreachable (carrier block / outage) — never as the primary path, never as a second source of truth.
- **Apps must not see each other's user identity.** Pairwise `sub` keeps Muhabbet and Sarnıç from correlating the same person.

This is the existing SSO/identity-hub direction (`docs/SSO_APP_LAUNCHER_DESIGN.md`) made concrete and applied to the whole suite.

---

## 2. What FIVUCSAS already does — do NOT rebuild these

The deep-study confirmed these are **already configurable**; treat them as platform features, not work:

| Capability | How | Evidence |
|---|---|---|
| Per-tenant, admin-configurable login flows | `POST /tenants/{id}/auth-flows` with `FlowStepSpec` | `AuthFlowController.java:55-62`, `CreateAuthFlowCommand.java:17-29` |
| Config-driven login engine (change flow w/o redeploy) | `APP_AUTH_CONFIG_DRIVEN_LOGIN[_TENANTS]` | `ConfigDrivenLoginPolicy.java:49-68` |
| 12 selectable login methods incl. SMS_OTP, PASSKEY | `AuthMethodType` LOGIN_METHODS | `AuthMethodType.java:9,46-59` |
| Hosted OIDC: Authorization Code + PKCE, JWKS, discovery | `/oauth2/authorize|token|userinfo`, `/.well-known/*` | `OAuth2Controller.java`, `OpenIDConfigController.java` |
| `phone_number` / `email` / `profile` claims by scope | id_token + `/userinfo`, scope-gated | `OAuth2Service.java:467-480,662-682` |
| Per-app OAuth2 client (confidential) via REST | `POST /oauth2/clients` (TENANT_ADMIN) | `OAuth2ClientController.java:87-131` |
| Refresh-token rotation w/ family reuse-detection | `grant_type=refresh_token` | `OAuth2Service.refreshAccessToken` 528-574 |
| Pairwise `sub` (apps can't correlate users) | `APP_IDENTITY_OIDC_SUBJECT_IDENTITY=true` + salt | `PairwiseSubjectResolver.java:77-129` |
| JS SDK + widget: theme, locale, scope, mobile redirect | `FivucsasAuth` (Custom Tabs / AppAuth / loopback) | `web-app/.../FivucsasAuth.ts` |
| E.164 Turkish phone enforced at DB | CHECK constraint | `V54__users_phone_number_e164.sql` |

**Implication:** the previously-feared "blockers" (phone anchor, per-app flows, client registration, pairwise sub, SDK/mobile) are **configuration**, not platform gaps.

---

## 3. The genuine work — phased

Classification per item: **CONFIG** (already possible, listed for sequencing) · **CODE FIX** · **BUG** · **INFRA** · **GAP (optional)**.

### Phase 1 — Make FIVUCSAS a safe *shared* IdP (unblocks both apps)

| # | Item | Class | Effort | Flag | Why / evidence |
|---|---|---|---|---|---|
| **F1** | **Bind refresh tokens to their issuing client** | **BUG (P0)** | M | 🚩 grace-window | `refreshAccessToken` resolves a token by wire value only (`OAuth2Service.java:539`) and never checks it was issued to this `client_id`; `refresh_tokens` has no client column (`V6__create_refresh_tokens_table.sql`). A Muhabbet refresh token is replayable by the Sarnıç client. **Must close before two apps share the deployment.** Fix: add nullable `client_id` (migration) + stamp in `createRefreshToken` + reject mismatch in the grant; legacy-null tokens accepted during a grace window so `/auth/refresh` keeps working. ~1 migration + ~15-20 LOC. |
| **F2** | **SMS_OTP login sets `phone_number_verified`** | **CODE FIX** | S | — | `user.verifyPhone()` is called only by the standalone `POST /auth/verify-phone` (`AuthController.java:506`); the login handlers `SmsOtpVerifyMfaStepHandler.verify` (29-46) and `SmsOtpAuthHandler` (49) never set it. So a Muhabbet user who logs in by SMS every day still ships `phone_number_verified:false`. Fix: set+persist the flag on successful SMS_OTP login (mirrors the email path). 1 line. |
| **F3** | **Ensure every Muhabbet user has a phone** | CONFIG / small | S | — | Self-service register has no phone field (`RegisterUserCommand.java:24-29`). Either make SMS_OTP a **Layer-1 required** factor in Muhabbet's tenant flow (forces phone at first login — pure config) or add phone to the register command (minor additive). Pairs with F2 to make the verified-phone claim reliable — Muhabbet's contact-sync anchor. |
| **F4** | **Programmatic public-PKCE / cross-tenant client provisioning** | **GAP (optional)** | S | — | `RegisterClientRequest` exposes only `appName/redirectUris/scopes` (`OAuth2ClientController.java:259-268`) → API-made clients are always `confidential=true`, `cross_tenant=false`. A **public PKCE** client (Muhabbet native/SPA) can today only be made by SQL/Flyway seed (the V80/V82 pattern). Choose: (a) document the Flyway-seed runbook (works now, zero code), or (b) add `confidential`/`crossTenant` to the request DTO + builder (~10 LOC). |
| **F5** | **Reachability: front the origins with a TR-PoP CDN** | **INFRA (P0)** | M | — | `api.fivucsas.com`, `muhabbet-api`, `sarnic-api` all resolve to **one Hetzner IP (116.203.222.213)** that specific Turkish mobile carriers block — so all three are unreachable together on those networks. Server is healthy (OIDC discovery 200 in 0.16s); the block is carrier-side IP filtering, not our config. Fix: put the hostnames behind a **non-Cloudflare** CDN with a Turkish PoP (Bunny.net — already in the stack — or Gcore/Fastly). One change fixes reachability for the whole suite. Confirm the mechanism first with a phone-side `curl -v` on the blocked carrier. |
| **F6** | **Enable pairwise `sub` + fix a permanent salt** | CONFIG (decision) | S | — | Before a 2nd app integrates, set `APP_IDENTITY_OIDC_SUBJECT_IDENTITY=true` + a stable `app.identity.pairwise-salt` (`PairwiseSubjectResolver.java:77-87`) so Muhabbet and Sarnıç get different `sub` for the same person. Salt is global and must never rotate post-launch — **owner decision required**. |

**Phase 1 exit:** F1 + F2 merged and CI-verified; a public Muhabbet client + a confidential Sarnıç client exist; the suite is reachable from a previously-blocked TR carrier; pairwise sub on with a fixed salt.

### Phase 2 — OIDC standards completeness & RP ergonomics

| # | Item | Class | Effort | Why |
|---|---|---|---|---|
| F7 | Advertise real grant types in discovery | CODE FIX | S | `grant_types_supported=["authorization_code"]` (`OpenIDConfigController.java:65`) hides the working `refresh_token` grant; strict RP libraries may refuse to use it. |
| F8 | RFC 7662 token introspection endpoint | GAP | M | Lets RP resource servers validate access tokens server-side without `/userinfo`. JWKS-offline + `/userinfo` is the current (valid) substitute; introspection is the standards-complete option. |
| F9 | `client_credentials` grant (M2M) | GAP (optional) | M | Only if a service-to-service (no user) flow is ever needed. ~half a day: new grant branch in `OAuth2Controller.token` + service method. |
| F10 | Dynamic client registration (RFC 7591) | GAP (optional) | M | Only if FIVUCSAS becomes a true *external* product with third-party self-service. Not needed for first-party apps. |

### Phase 3 — Security & operational professionalization

| # | Item | Class | Effort | Why |
|---|---|---|---|---|
| F11 | RSA signing-key rotation mechanism + runbook | GAP (P1) | M | A single static RSA key signs all RS256 tokens with no rotation path; a compromise or rotation breaks every RP at once. Add a `kid`-keyed JWKS with overlap (mirror the `HsKeyRegistry` pattern used for HS secrets) + a runbook **before** external apps depend on RS256. |
| F12 | Make the Testcontainers integration gate genuinely green + required | QUALITY (P1) | L | The cross-tenant isolation IT gate has been bypassed with one-time admin-merge exceptions; it must run and block. This is the IdP — its tenant-isolation tests are load-bearing. |
| F13 | OAuth-flow audit + observability | QUALITY | M | Structured audit of authorize/token/refresh/consent + metrics, so RP integration issues are diagnosable. |
| F14 | Consent / scope-governance screen | GAP | M | Required only if/when non-first-party clients integrate. |

### Phase 4 — Client-side integration (per app — lands in the app repos)

| App | Work | Notes |
|---|---|---|
| **Sarnıç** (first) | Register a **confidential** OIDC client; replace the hardcoded email/password screen with FIVUCSAS hosted login driven by the tenant flow; validate RS256 offline via JWKS; **keep password login as the FIVUCSAS-unreachable fallback only**. | Cleanest fit (institutional, email-based). Sequenced after Phase 0 access-control fixes + F1/F5. |
| **Muhabbet** (after) | Register a **public PKCE** client (AppAuth/Custom Tabs, scheme `muhabbet://...`); tenant flow = SMS_OTP Layer-1 (F2/F3) so contact-sync gets a verified phone; native OTP (Twilio) demoted to **fallback only**. | After F1/F2/F3/F5/F6. The Phase-0 Twilio wiring becomes the fallback path, not throwaway. |
| **Future apps** | Pattern: seed client → configure tenant flow → integrate SDK/AppAuth → validate RS256 via JWKS → thin fallback. | No app-side auth logic to maintain. |

---

## 4. Concern classification (the honest split)

| Concern | Classification |
|---|---|
| Per-app tenants + independent flows | **CONFIG** — dissolves |
| SMS_OTP anchor + `phone_number` claim (core) | **CONFIG** — dissolves |
| Pairwise `sub` to de-correlate apps | **CONFIG** — flag + salt |
| Confidential per-app client registration | **CONFIG** — REST API |
| RS256/JWKS offline validation + `/userinfo` | **CONFIG** — already the design |
| SDK theming / locale / scope / mobile redirect | **CONFIG** — dissolves |
| `phone_number_verified` reliable on SMS login (F2) | **CODE FIX** — 1 line |
| Refresh token not client-bound (F1) | **CODE BUG** — 1 migration + ~15 LOC |
| Public/cross-tenant client via REST (F4) | **GAP (optional)** — SQL seed works today |
| introspection / client_credentials / dynamic-reg | **GAP (mostly optional)** — JWKS+userinfo substitutes |
| RSA key rotation (F11) | **GAP (P1 hardening)** |
| Reach api.fivucsas.com from TR (F5) | **INFRA** — carrier block, orthogonal to auth |

---

## 5. Sequencing & gates

```
F1 (client-bind refresh)  ─┐
F5 (reachability CDN)      ─┼─►  Sarnıç client integration (Phase 4)  ─►  Muhabbet client integration
F2+F3 (verified phone)    ─┘                                              (needs F2/F3/F6 too)
F6 (pairwise sub + salt)  ──►  REQUIRED before the 2nd app integrates
```

**Hard rule:** F1 (refresh-token client binding) and F6 (pairwise sub) must be in place **before two apps share the deployment**, or one app can replay another's tokens / correlate its users.

**Two code items are the whole critical path on the FIVUCSAS side:** **F1** (small security bug) and **F2** (one line). Everything else is config you flip, a SQL seed, infra, or optional standards-completeness.
