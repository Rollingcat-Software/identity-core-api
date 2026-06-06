# SECURITY NOTE — Stale env file committed to git (2026-06-06)

## Severity: LOW — a stale secret-shaped file was committed; NO live credential was leaked

The file `.env.hetzner` was committed **tracked** (it slipped past `.gitignore`) in
commit `f9f0f2d` and that commit is on `origin/main`. The file contains
password-shaped values, so on first glance it looks like a production secret leak.

**It is not.** Verified on the production host on 2026-06-06: every secret value in
`.env.hetzner` is **stale and inert** — none of them authenticate to any live
service. The real production secrets live only in `.env.prod`, which has **never**
been git-tracked.

> **Action required: none beyond the hygiene fix on this branch.**
> Do **NOT** rotate Postgres / Redis / JWT for this incident, do **NOT** restart
> `shared-postgres` / `shared-redis`, do **NOT** redeploy. Rotating would risk a
> multi-app outage (Postgres + Redis are shared across ~6 apps) for **zero**
> security benefit, because the exposed values are already dead.

| Secret | Value in `.env.hetzner` (the leaked file) | Live? |
|--------|-------------------------------------------|-------|
| `JWT_SECRET` | sha256 `726f5b26…` — matches the decommissioned GCP-era key, **not** live | **STALE / INERT** |
| `DB_PASSWORD` | sha256 `c0b3f4ff…` — matches neither live nor GCP | **STALE / INERT** |
| `REDIS_PASSWORD` | sha256 `3a4c40dd…` — matches neither live nor GCP | **STALE / INERT** |

> This document contains **no secret values** — only short, non-reversible sha256
> prefixes of the *dead* values, for audit traceability. The live `.env.prod`
> fingerprints are intentionally not recorded here.

---

## Verification (how the "inert" conclusion was reached)

Run on the Hetzner host, 2026-06-06, against the live checkout
`/opt/projects/fivucsas/identity-core-api`:

1. **The live file was never committed.**
   `git log --oneline -- .env.prod` → **0 commits**. `.env.prod` (mode 600,
   host-local) is the only file holding production secrets and has never been
   tracked → never leaked.

2. **The committed file is `.env.hetzner` only** (plus the historical, already-
   untracked `.env.gcp`). `git log -- .env.hetzner` → added in `f9f0f2d`;
   `git ls-tree origin/main` → present. That is the entire exposure surface.

3. **Leaked values ≠ live values.** Comparing sha256 fingerprints of the actual
   values (never the values themselves): `JWT_SECRET`, the DB password, and the
   Redis password in `.env.hetzner` all **differ** from the corresponding live
   values in `.env.prod`. The leaked `JWT_SECRET` matches the old `.env.gcp`
   (GCP era, now decommissioned); the leaked DB/Redis passwords match nothing live.

4. **The container loads `.env.prod`, not `.env.hetzner`.**
   `docker-compose.prod.yml` populates the api's `environment:` block from
   `--env-file .env.prod` at deploy time. So the runtime credentials are the live
   `.env.prod` set, which was never exposed.

**Conclusion:** the committed credentials cannot authenticate to production. The
exposure is a hygiene defect, not a credential compromise.

---

## Operative remediation (this branch — done)

The fix is to stop tracking the stale file and close the `.gitignore` gap that let
it in (`*.env` does not match a file named `.env.hetzner`):

```bash
git rm --cached .env.hetzner          # remove from tracking; keep the file on disk
# .gitignore now has a catch-all:
#   .env
#   .env.*        <- matches .env.hetzner / .env.prod / .env.gcp / .env.staging
#   *.env
#   !.env.example <- the only env file that stays tracked
```

That is the complete remediation for this incident. No rotation, no restart, no
redeploy.

### Optional infra-level confirmation (not required)
If extra assurance is wanted, prove inertness directly by attempting the **leaked**
DB and Redis passwords against the live services and confirming they **fail** (lock
nothing out). PASS = leaked creds are dead, exactly as the fingerprint comparison
already shows.

---

## History note — why a history purge is NOT warranted here

The stale values remain readable in git history at `f9f0f2d` on `origin/main`.
Removing a blob from history needs `git filter-repo`/BFG + a **force-push to
`main`**, which:
- is **BLOCKED** in this environment (`git push --force*` is hard-denied; direct
  pushes to the protected default branch are denied), and
- breaks every existing clone/fork and is coordination-heavy.

Because the exposed values are **already dead**, a history rewrite buys no security
and is not worth its operational risk. The `.gitignore` hardening + `git rm
--cached` on this branch prevents any re-leak going forward, which is sufficient.

---

## REFERENCE ONLY — credential rotation procedure

> ⚠️ **Do NOT run any of the following for the 2026-06-06 `.env.hetzner` incident.**
> The leaked values are stale/inert (see Verification above) and Postgres/Redis are
> shared across ~6 apps. These steps are retained **only** as a tested runbook to
> execute **IF a future audit ever confirms that a genuinely LIVE secret was
> committed.** In that case, verify the leaked value matches the live value first,
> then rotate only the affected secret.

### Pre-flight (reference)

```bash
ssh -i ~/.ssh/hetzner_ed25519 root@<host>
cd /opt/projects/fivucsas/identity-core-api
# DB target: shared-postgres:5432/identity_core, user `postgres`; cache: shared-redis
cp .env.prod ".env.prod.bak.$(date +%Y%m%d-%H%M%S)"   # backup BEFORE editing
chmod 600 .env.prod.bak.*
```

### (a) Postgres password (reference — shared role, rotate with care)

```bash
NEWPG="$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-40)"
docker exec -i shared-postgres psql -U postgres -d identity_core \
  -c "ALTER ROLE postgres WITH PASSWORD '$NEWPG';"
# set POSTGRES_PASSWORD=<new> in .env.prod, then:
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d identity-core-api
# verify: docker logs --tail=50 identity-core-api (clean datasource/Flyway), health UP
```
> `postgres` is a **shared** role — rotating it requires updating EVERY app's env
> file in lockstep, or they all lose DB access. Do not re-init the data volume.

### (b) Redis password (reference — shared instance)

```bash
NEWREDIS="$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-40)"
docker exec -i shared-redis redis-cli CONFIG SET requirepass "$NEWREDIS"
docker exec -i shared-redis redis-cli -a "$NEWREDIS" CONFIG REWRITE
# set REDIS_PASSWORD=<new> in .env.prod (and every other app's), then:
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d shared-redis identity-core-api
# verify: docker exec -i shared-redis redis-cli -a "$NEWREDIS" PING -> PONG
```
> Redis is **shared** and backs MFA/approve-login/QR sessions — a rotation drops
> in-flight MFA sessions and requires updating every app's env in lockstep.

### (c) JWT secret (reference)

```bash
NEWJWT="$(openssl rand -base64 64 | tr -d '\n')"
# set JWT_SECRET=<new> in .env.prod; keep APP_SECURITY_JWT_AUDIENCE non-blank
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d identity-core-api
# verify: api boots, health UP, fresh login mints valid token, old tokens rejected
```
> **Lower-disruption alternative (HS key rotation, PR #64):** `HsKeyRegistry`
> supports kid-routed HS secrets. The legacy kid is `hs-2026-04`. Introduce a NEW
> active kid + secret and demote the old one to verify-only, then drop it after the
> access-token TTL — rotating signing material without a hard logout of everyone.

---

## Checklist (this incident)

- [x] Confirmed `.env.prod` (live secrets) was never git-tracked
- [x] Confirmed `.env.hetzner` leaked values are STALE/INERT (≠ live, fingerprint-verified)
- [x] `git rm --cached .env.hetzner` + `.gitignore` catch-all (`.env.*` / `!.env.example`)
- [ ] PR merged to `main`
- [ ] (optional) Infra-level inertness test: leaked DB/Redis passwords rejected by live services
- [ ] No rotation performed — not required for this incident
