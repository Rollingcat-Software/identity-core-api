# Identity & Account-Linking — Design (Model A: IdP-authority biometrics)

Status: **APPROVED 2026-05-29** (operator). Drives a phased build (Phases 1–4).
Owner: identity-core-api (+ web-app, biometric-processor).

## Problem
The same person operating multiple tenant accounts (e.g. `ahabgu@gmail.com` @ Fivucsas
and `ahmet.abdullah@marun.edu.tr` @ Marmara) must re-enrol biometrics per account.
Today one `users` row fuses three concerns: the **person**, their **authentication
identity** (credentials/biometrics), and their **tenant membership** (role/relationship).
Because biometrics hang off the tenant-membership row, they are duplicated per tenant.

Sharing one raw biometric template across tenants is **not** the fix — it would breach
tenant isolation (the `@Filter` hardening, P0-1) and KVKK/GDPR special-category rules,
and create cross-tenant linkability + a single point of compromise.

## Decision — Model A (IdP-authority)
Introduce a **person/identity** layer. `users` rows become **tenant memberships** that
reference an `identity`. The biometric template lives **once**, owned by the identity and
held by the biometric-processor acting as the **IdP biometric authority**. Tenants never
receive the raw template; they receive a **per-(identity,tenant) consent grant** to
*verify* against it. Enrol once; joining a new tenant is a consent toggle, not a re-capture.

```
identity (the person)
  ├─ identity_emails: ahabgu@gmail.com (verified), ahmet.abdullah@marun.edu.tr (verified)
  ├─ biometric template (ONE, held by biometric-processor keyed by identity_id)
  ├─ identity_tenant_biometric_consent: {Fivucsas: granted, Marmara: granted}
  └─ memberships (users rows):
       ├─ users @ Fivucsas (TENANT_ADMIN)
       └─ users @ Marmara  (TENANT_ADMIN)
```

### Why Model A (vs alternatives)
- **B (per-tenant copy on link):** DRY-ish but each tenant holds a raw template → higher
  linkability + more compromise surface. Rejected.
- **C (email-link only, biometrics stay per-tenant):** strongest isolation but does not
  solve the re-enrol UX. Rejected as the end-state (it is effectively the Phase-1/2 interim).

## Phases (each ships independently and is reversible)

### Phase 1 — Identity layer, ZERO behavior change  *(foundation, must land first)*
- `V65 identities`, `V66 identity_emails`, `V67 users.identity_id` (FK, nullable).
- Backfill: every existing `users` row → its own new `identity` (1:1), its email →
  one verified `identity_emails` row. No auth/JWT/UX change. After backfill, a later
  migration can `SET NOT NULL` once 100% populated.
- JPA: `Identity`, `IdentityEmail` entities (+ `@Filter`? NO — identities are
  cross-tenant by definition; they are NOT tenant-scoped. Document this explicitly so
  the P0-1 ratchet isn't misapplied). `users.identity` `@ManyToOne` (read-mostly).
- Repos/ports. No controller surface yet (internal only).

### Phase 2 — Account linking (emails / SSO), NO biometric sharing yet
- `POST /api/v1/identity/link/initiate {email}` → sends OTP to the target email
  (proves control of the other account's email).
- `POST /api/v1/identity/link/confirm {email, otp}` → **step-up required** (re-auth with
  an existing strong factor on the CALLER, or a biometric match) → re-points the target
  user's `identity_id` to the caller's identity. Audited `IDENTITY_LINKED` (actor = caller
  user id, resource = identity). Reversible: `POST /api/v1/identity/unlink {membershipId}`.
- Guardrails: never auto-merge by name; require BOTH (a) proof of control of the target
  email (OTP) AND (b) caller step-up; both memberships must be ACTIVE; block linking two
  memberships **in the same tenant** (would duplicate a membership). Rate-limited.
- `GET /api/v1/identity/me` → the person view: linked emails + memberships (tenant, role).
- web: "Linked accounts" section in Profile (list memberships, link/unlink, switch).

### Phase 3 — Biometric on the identity + per-tenant consent (Model A core)
- `V68 identity_tenant_biometric_consent(identity_id, tenant_id, granted, granted_at,
  revoked_at)`. Default: a membership does NOT auto-consent — explicit opt-in per tenant.
- biometric-processor: re-key the face/voice template store by **identity_id** (one row
  per person). New endpoints accept `identity_id`; legacy `user_id` calls resolve to the
  identity via the api. Migration maps existing per-user embeddings → the user's identity
  (dedupe: keep the highest-quality template when a person has multiple).
- Verify path: `verify(identity_id, tenant_id, probe)` returns a decision ONLY when
  `consent(identity, tenant)=granted`; the tenant/app never receives the raw template.
- **Re-audit isolation** (adversarial tests, like P0-1): a tenant without consent must get
  NO verification signal; cross-tenant probe must not leak. New `IdentityBiometricConsentIT`.
- web: enrolment UX becomes "enrol once"; per-tenant a consent toggle ("Use my FIVUCSAS
  face for Marmara"). Re-enrol only to update the template.

### Phase 4 — OIDC `sub` alignment (flag-gated, LAST)  *(IMPLEMENTED — ships DORMANT)*
- Make the OIDC subject identity-stable per relying party (`sub` = identity-derived
  PAIRWISE id), so federated relying parties see a consistent person across tenants
  while different RPs get unlinkable subs. Behind `app.identity.oidc-subject-identity`
  flag (**default OFF**). Soak behind the flag in staging before flipping prod.
- **Scope:** ONLY the OIDC/OAuth2 surfaces — the id_token `sub` (`OAuth2Service.exchangeCode`)
  and the `/oauth2/userinfo` subject (`OAuth2Service.getUserInfo`). JWKS is unaffected.
  The internal dashboard access-token subject (the user principal/email) is **unchanged** —
  Phase 4 only re-points the OIDC id_token/userinfo subject.
- **Algorithm** (flag ON), implemented in `infrastructure.oauth2.PairwiseSubjectResolver`:
  ```
  sector       = OAuth2Client.sectorIdentifier()   # OIDC Core §8.1: host of the
                                                    #   registered redirect_uri, else clientId
  localAccount = user.identity_id                   # the PERSON (cross-tenant); falls back to
                 (user.id pre-backfill if NULL)     #   user.id while V67 backfill is incomplete
  salt         = app.identity.pairwise-salt         # per-env, stable + secret
  sub          = base64url( SHA-256( sector + "|" + localAccount + "|" + salt ) )
  ```
  Properties: deterministic/stable per (identity, RP); unlinkable across RPs (distinct
  sectors); opaque (one-way hash never exposes the raw `identity_id`); same person → same
  `sub` for a given RP across all their tenant accounts (Model A goal).
- **Default-OFF guarantee:** with the flag off the resolver returns exactly
  `user.id.toString()` — byte-identical to the pre-Phase-4 path; the discovery doc keeps
  `subject_types_supported: ["public"]`. With the flag on it advertises `["pairwise"]`.
  Proven by `PairwiseSubjectResolverTest` (off==legacy; on==stable/per-RP/≠identity_id).
- **Config:** `app.identity.oidc-subject-identity` (`APP_IDENTITY_OIDC_SUBJECT_IDENTITY`,
  default false) + `app.identity.pairwise-salt` (`APP_IDENTITY_PAIRWISE_SALT`). Flipping the
  flag (or rotating the salt) rotates every RP's view of `sub` — coordinate with RPs.
- No Flyway migration (flag only). Reversible: flip the flag back to false.

## Cross-cutting rules
- **Identities are NOT tenant-scoped** — no `@Filter(tenantFilter)` on `Identity`/
  `IdentityEmail`/consent. They are platform-level. (Tenant isolation is preserved at the
  **membership** (`users`) and **consent** layers, not by hiding the identity.)
- **Auth unchanged through Phase 1–2**: JWT still keyed by `users` id; `identity_id` is
  additive. Only Phase 4 touches `sub`.
- **Privacy**: linking + consent are explicit, verified, audited, reversible. KVKK posture:
  biometric authority = the IdP (one controller for the template); tenants are verifiers
  under per-tenant consent.
- **Compliance with P0-1**: every new tenant-scoped read still carries the filter; new
  cross-tenant tables (identities/emails/consent) are deliberately un-filtered and covered
  by their own access tests.

## Migration order (Flyway)
V65 identities → V66 identity_emails → V67 users.identity_id (+backfill) →
V68 identity_tenant_biometric_consent. (Phase 4 needs no schema; flag only.)
Each migration must apply cleanly from the current prod schema; verify on the staging DB
(127.0.0.1:18080, see RUNBOOK_STAGING.md) before prod.

## Rollout / validation
- Phase 1: deploy, confirm zero behavior change (existing logins/enrol/admin all unchanged;
  every user has an identity + verified email row).
- Phase 2: validate link/unlink on staging with two seeded accounts; audit rows correct.
- Phase 3: adversarial consent/isolation tests green on staging before prod; verify a
  no-consent tenant gets no signal; bio boot via `Dockerfile.liveness-overlay`.
- Phase 4: flag OFF in prod; soak in staging with the flag ON.

## Risks
- Account merge is destructive + sensitive (two TENANT_ADMINs) → verified + reversible.
- Phase 3 touches the most sensitive data + the isolation just hardened → own IT suite.
- Phase 4 `sub` change is wide → flag-gated, last, reversible.
