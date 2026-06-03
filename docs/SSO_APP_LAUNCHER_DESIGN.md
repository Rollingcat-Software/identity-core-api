# FIVUCSAS SSO App Launcher — Design (DRAFT)

**Status:** Draft for review · **Date:** 2026-06-02 · **Owner:** Ahmet (idea), Claude (design)

> This is a brainstorming/design document. Nothing here is implemented. It captures
> the idea, grounds it in what the platform already has, proposes an architecture,
> and lays out a phased plan + open decisions. No code is written until the design
> is approved.

---

## 1. The idea (as described)

> "We provide login from mobile web and mobile app to the dashboard. We could also
> provide navigation to all registered apps for a user. As an identity I'm registered
> to FIVUCSAS and Marmara University; I should be able to jump to the dashboards of
> those registered platforms. A tenant could be any platform — Canvas, Canva,
> Microsoft, etc. — any tenant I'm already a member of. So we give the user a
> **shortcut** and they're redirected, **already authenticated**, to that platform's
> dashboard. No need to go to `verify.fivucsas.com` and log in again and again.
> Log in once to FIVUCSAS, then from FIVUCSAS navigate — auto-authenticated — to
> every tenant platform you're already a member of. E.g. my identity is a member of
> FIVUCSAS + Marmara University, so from `app.fivucsas.com` (or the mobile app) I get
> a direct shortcut into `demo.fivucsas.com` (BYS demo) instead of going to
> `demo.fivucsas.com` and logging in again."

**In one line:** turn FIVUCSAS from "an auth widget tenants embed" into an
**identity hub / SSO portal** — a single home that lists every app the signed-in
person can access and launches each one already authenticated, with one login.

This is the **Okta MyApps / Microsoft Entra MyApps / Google app-launcher** pattern.

### What "the dashboard" means here
There are two surfaces a user signs into FIVUCSAS itself from:
- `app.fivucsas.com` (web dashboard) and the **mobile app** — these become the
  **launcher home**.
The launcher home shows **app tiles**; clicking a tile lands the user, already
authenticated, in *that app's* dashboard (e.g. the Marmara BYS demo at
`demo.fivucsas.com`), with no second login.

---

## 2. What we already have (grounding — verified in the codebase)

| Building block | Status | Where |
|---|---|---|
| OAuth 2.0 / OIDC authorization server (authorize, token, JWKS, discovery, PKCE S256, state/nonce, exact-match redirect allowlist) | ✅ shipped | `OAuth2Controller`, `OAuth2Service` |
| Pairwise `sub` per client | ✅ shipped | `PairwiseSubjectResolver` |
| Hosted login (full credential + MFA ceremony) → `POST /oauth2/authorize/complete` mints the code | ✅ shipped | `verify.fivucsas.com`, `OAuth2Controller.authorize/complete` |
| Identity / person layer: one person ↔ many tenant memberships | ✅ shipped | `/identity/me` → `IdentityMeResponse(emails[], memberships[]{userId, tenantId, tenantName, role})` |
| Account linking + **membership switch** (swap active membership, re-issue tokens) | ✅ shipped | `MembershipSwitchController`, `POST /auth/switch-membership` |
| Registered OIDC clients per tenant, with **cross_tenant** first-party flag (V82) | ✅ shipped | `OAuth2Client` (client_id, client_name, redirect_uris, allowed_scopes, tenant, active, confidential, cross_tenant) |
| Cross-site **app-switcher web component** (`<fivucsas-launcher>`, `app.fivucsas.com/launcher.js`) — currently hardcoded FIVUCSAS-suite links + EN/TR | ✅ shipped (UI precedent) | web-app `public/launcher.js` |

**The gaps (what this feature actually adds):**
1. **No SSO session at the authorization server.** Today every `/oauth2/authorize`
   runs the full hosted-login ceremony and ends at `/authorize/complete` with a
   *fresh, single-use* MFA session. There is no persistent "I am already logged in
   to FIVUCSAS" session the AS can reuse. **This is the core new capability.**
2. **No silent / `prompt=none` authorize path** that reuses an existing session to
   mint a code without UI.
3. **No launcher metadata on clients** — `OAuth2Client` has no logo, launch URL,
   "show in launcher" flag, app category, or per-app re-auth policy.
4. **No "list my apps" API** and no launcher UI driven by it (the existing
   web-component is hardcoded suite links, not membership-driven SSO tiles).
5. **No third-party (non-FIVUCSAS) SaaS SSO** (Canvas/Canva/Microsoft) — that needs
   FIVUCSAS to act as an external IdP (IdP-initiated SSO, SAML and/or OIDC).

---

## 3. Core mechanic — "login once, launch many"

The whole feature hinges on an **SSO session** held by the authorization server on
the auth origin (`verify.fivucsas.com` / `api.fivucsas.com`), established the first
time the user completes the full login+MFA ceremony.

```
First login (full ceremony, once):
  user → verify.fivucsas.com → credentials + MFA → /authorize/complete
       → mint code for app A  AND  set a secure, HttpOnly SSO session cookie
         (server-side session: identityId, active membership, AMR, auth_time, acr)

Launch app B from the FIVUCSAS launcher (silent):
  launcher tile B → GET /oauth2/authorize?client_id=B&redirect_uri=…&prompt=none
       → AS sees a valid SSO session that satisfies B's policy
       → mints a code immediately (NO credential/MFA UI)
       → 302 to B's redirect_uri?code=… → B exchanges code → user is in B's dashboard
```

The user *does* still pass through the standard OIDC `/authorize` endpoint for each
app (that is how each app gets its own correctly-scoped, pairwise-`sub` token) — but
it is **invisible and instant** because the session already exists. We are not
bypassing OIDC; we are adding the session that lets OIDC do silent SSO, exactly like
every major IdP.

### Per-app re-authentication policy
Silent launch is gated by policy so it stays secure:
- **Session max-age** — silent auth only within a configurable window (e.g. 8–12h);
  past that, re-login.
- **Per-app `acr`/step-up** — an app can require step-up (e.g. a high-assurance
  tenant) even with a live session → AS prompts for the extra factor only, not a full
  re-login. Honors the existing MFA/auth-flow config.
- **`prompt=login`** support — an app/user can force fresh credentials.
- **Consent** — first launch of a new app shows a one-time consent (scopes/tenant),
  remembered thereafter (standard OIDC consent).

### Single Logout (SLO)
Logging out of FIVUCSAS should optionally end the SSO session and (best-effort)
notify apps via OIDC back-channel/front-channel logout. MVP: clear the SSO session +
local tokens; full SLO is a later phase.

---

## 4. Scope — two tiers (deliberately separated)

**Tier 1 — FIVUCSAS-native tenant apps (the MVP; e.g. the Marmara BYS demo).**
Apps that are already FIVUCSAS OIDC clients (`demo.fivucsas.com` = `marmara-bys-demo`).
We control both ends; it is pure OIDC silent SSO + a launcher. This delivers the
exact example in the idea ("jump from app.fivucsas into the BYS demo dashboard") and
is achievable by composing existing pieces + the SSO session.

**Tier 2 — Third-party SaaS (Canvas, Canva, Microsoft, …).**
FIVUCSAS becomes an **external IdP** for these SPs via **IdP-initiated SSO**, almost
always **SAML 2.0** (Canvas, many enterprise SaaS) and sometimes OIDC. This is a
much larger lift: a SAML IdP implementation (or an off-the-shelf one), per-SP
metadata/attribute-mapping/cert config, and each SaaS must be configured to trust
FIVUCSAS. It is the "any platform, any tenant" ambition but should NOT block Tier 1.

**Recommendation:** ship Tier 1 first; treat Tier 2 as a separate program once Tier 1
proves the launcher + SSO session.

---

## 5. Architecture & components

### 5.1 Backend (identity-core-api)
- **SSO session store** (new). Server-side session keyed by a secure HttpOnly cookie
  on the auth origin. Holds `identityId`, active `userId`/`tenantId`, `auth_time`,
  `amr`, `acr`, session max-age. Backed by Redis (already in stack). Created at
  `/authorize/complete`; revoked on logout/SLO.
- **Silent authorize** (extend `OAuth2Controller.authorize`). On `GET /authorize`
  with a valid SSO session that satisfies the client's policy: mint a code directly
  (skip hosted-login redirect). Support `prompt=none` (RFC: return `login_required`
  if no usable session), `prompt=login`, `max_age`, and per-client `acr`/step-up.
- **Client launcher metadata** (new migration extending `oauth2_clients`):
  `launcher_visible BOOLEAN`, `logo_url`, `launch_url` (or derive from the registered
  redirect/initiate-login URI), `app_category`, `display_order`, `reauth_policy`
  (e.g. `silent` | `step_up` | `always`). Reuse existing `client_name`.
- **"My apps" API** (new): `GET /launcher/apps` → for the caller's identity, for each
  membership in `/identity/me`, the launcher-visible clients of that tenant (+ the
  cross-tenant first-party ones), returning `{appId, name, logo, tenantName,
  launchUrl, reauthPolicy}`. This is the single source the launcher UI renders.
- **IdP-initiated launch** (new, thin): `GET /launcher/launch/{appId}` → builds the
  correct `/oauth2/authorize` (or SAML AuthnResponse in Tier 2) for that app and
  302s the browser, so the client doesn't need to construct OIDC params itself.

### 5.2 Web (web-app + the launcher component)
- **Launcher home** on `app.fivucsas.com` — evolve the existing `<fivucsas-launcher>`
  from hardcoded suite links into a **data-driven grid** fed by `GET /launcher/apps`.
  Tiles show app logo + name + tenant; click → `/launcher/launch/{appId}` (silent SSO)
  → app dashboard in a new tab / same tab.
- Reuse the existing account/workspace switcher for multi-membership identities.

### 5.3 Mobile (client-apps)
- A **"My Apps"** screen (mobile) listing the same `GET /launcher/apps` tiles.
- Launch a tile via the existing hosted-first plumbing (AppAuth/Custom Tab) hitting
  `/launcher/launch/{appId}` — which, with a live SSO session in the Custom Tab's
  cookie jar, completes silently and returns to the app or opens the target app.
  (Mobile SSO-session sharing across Custom Tabs is a known nuance — see Risks.)

### 5.4 Data flow (Tier-1 happy path)
1. User logs into FIVUCSAS once (full MFA) → SSO session cookie set.
2. `app.fivucsas` / mobile calls `GET /launcher/apps` → renders tiles (incl. "BYS
   Demo — Marmara University").
3. User taps "BYS Demo" → `GET /launcher/launch/marmara-bys-demo` → AS silent-authorize
   (session valid, policy = silent) → 302 to `demo.fivucsas.com/callback?code=…`.
4. demo exchanges the code → user is in the BYS demo dashboard. No second login.

---

## 6. Security model (must-haves)
- SSO session cookie: `HttpOnly`, `Secure`, `SameSite=Lax/Strict`, short max-age,
  rotation, bound to UA/IP-class where feasible.
- Silent auth strictly honors per-client `reauth_policy` + tenant MFA/auth-flow config
  (a tenant that mandates step-up is never silently bypassed).
- Consent screen on first launch of each app; revocable.
- Pairwise `sub` already isolates identity per client (keep).
- Audit every silent launch (who, which app, session id, acr) — extends existing
  audit_logs.
- SLO path so one logout can terminate the hub session.
- Reversibility: ship behind a flag (`app.auth.sso-session` default OFF); with it OFF,
  the system behaves exactly as today (full ceremony per authorize).

---

## 7. Phased implementation plan

**Phase 0 — Spec + decisions (this doc).** Lock MVP scope, re-auth policy, Tier-2
in/out.

**Phase 1 — SSO session + silent authorize (backend).**
SSO session store (Redis) + cookie; set it at `/authorize/complete`; extend `/authorize`
for silent mint + `prompt=none/login` + `max_age` + per-client policy. Feature-flagged
OFF. Tests + audit. *This is the heaviest, highest-risk phase and the linchpin.*

**Phase 2 — Client launcher metadata + "my apps" API.**
Migration extending `oauth2_clients`; `GET /launcher/apps`; `GET /launcher/launch/{appId}`.
Seed metadata for the existing first-party + Marmara clients.

**Phase 3 — Web launcher home.** Data-drive the launcher component from `/launcher/apps`;
silent-launch tiles; canary on one tenant (Marmara) end-to-end (app.fivucsas → BYS demo).

**Phase 4 — Mobile "My Apps".** Mobile launcher screen + Custom-Tab silent launch.

**Phase 5 — Hardening.** Consent UX, SLO, session management UI ("your active SSO
session / sign out everywhere"), per-app step-up flows.

**Phase 6 (separate program) — Tier 2 third-party SaaS.** SAML 2.0 IdP (+ OIDC RP
support), per-SP config, attribute mapping, IdP-initiated SSO for Canvas/Canva/MS/etc.

---

## 8. Decisions (locked 2026-06-02)
1. **MVP scope:** ✅ **Tier 1 only** — FIVUCSAS-native tenant apps (OIDC clients we
   control, e.g. the Marmara BYS demo). No third-party SaaS in v1.
2. **Re-auth default:** ✅ **Silent within a session window** (~8–12h after a full
   login); re-login after expiry; per-app / per-tenant step-up still honored for
   high-assurance flows.
3. **Tier-2 (third-party SaaS / SAML):** ✅ **North star (someday)** — a separate
   program after Tier 1 proves out; do NOT build a SAML IdP for v1.
4. **Launch target (default, revisit in UX):** new tab on web; on mobile, Custom Tab
   (or the target's installed app if a deep link exists). Minor — not blocking.
5. **Tile curation (default):** auto-list every `launcher_visible` client of the
   tenants the person is a member of; a tenant-admin visibility flag controls what
   appears; user pin/hide is a later nicety. Minor — not blocking.

---

## 9. Risks / hard parts
- **SSO session = the crown-jewel security surface.** A bug here is a cross-app
  account-takeover vector. Needs careful review, step-up policy, short TTL, audit.
  Aligns with the "reversible risky changes" rule → flag-gated, dark→canary→broad.
- **Mobile SSO session sharing** across Chrome Custom Tabs can be inconsistent
  (per-app cookie jars, ITP-like behavior); may need an app-held refresh/SSO artifact
  rather than relying purely on the Custom Tab cookie.
- **Tier-2 SAML is a real subsystem**, not a feature — scope it separately.
- **Logout / SLO** complexity grows with the number of connected apps.
- Don't regress today's per-authorize isolation: the minted token must still carry the
  user's real tenant_id + pairwise sub.

---

## 10. Verdict (short)
Strong, on-strategy, and ~80% pre-built. Tier 1 (the Marmara BYS-demo example) is a
**compose-what-we-have + add an SSO session** effort and is very achievable. Tier 2
(arbitrary SaaS) is a separate, larger IdP program. The SSO session is the linchpin and
the main security weight — build it flag-gated and canary it.
