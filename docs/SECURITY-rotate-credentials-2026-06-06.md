# SECURITY RUNBOOK — Rotate Compromised Credentials (2026-06-06)

## Severity: HIGH — Live secrets leaked to a public-history commit

The file `.env.hetzner` was committed **tracked** (not gitignored) in commit
`f9f0f2d` and that commit is **already pushed to `origin/main`**. Anyone with read
access to the repository history can recover the following secrets:

| Secret | Container env var | Source var (`.env.hetzner`) | Status |
|--------|-------------------|------------------------------|--------|
| JWT signing secret | `JWT_SECRET` | `JWT_SECRET` | **COMPROMISED** |
| PostgreSQL password (`postgres` @ `identity_core`) | `DATABASE_PASSWORD` | `POSTGRES_PASSWORD` | **COMPROMISED** |
| Redis password (`shared-redis`) | `REDIS_PASSWORD` | `REDIS_PASSWORD` | **COMPROMISED** |

> This runbook contains **no secret values**. Generate new secrets at rotation
> time and never paste them into the repo, a PR, an issue, or chat.

The working-tree fix (this branch `claude/untrack-env-hetzner-secret`) only stops
*future* tracking via `git rm --cached` + a hardened `.gitignore`. **It does NOT
remove the secrets from the existing history.** The only operative remediation is
to **ROTATE all three secrets on the production server immediately** (steps below).
See "History note" at the bottom for why a history purge is not the fix here.

---

## Pre-flight

```bash
# Connect to the production server (Hetzner)
ssh -i ~/.ssh/hetzner_ed25519 root@116.203.222.213

# Work as the deploy user / project dir used for this service
cd /opt/projects/fivucsas/identity-core-api
# (the compose project is identity-core-api; DB jdbc target is
#  shared-postgres:5432/identity_core, user `postgres`; cache is shared-redis)
```

Take a timestamped backup of the host-local env file BEFORE editing (it holds the
old, now-burned secrets — keep it `chmod 600`, never commit; `.gitignore` already
blocks `.env.*` and `*.env`):

```bash
cp .env.prod ".env.prod.bak.$(date +%Y%m%d-%H%M%S)"
chmod 600 .env.prod.bak.*
```

---

## (a) Rotate the PostgreSQL password

1. Generate a new strong password locally (do not echo it into history):

   ```bash
   NEWPG="$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-40)"
   ```

2. Apply it on the running Postgres role (the api connects as `postgres` to
   database `identity_core`):

   ```bash
   docker exec -i shared-postgres \
     psql -U postgres -d identity_core \
     -c "ALTER ROLE postgres WITH PASSWORD '$NEWPG';"
   ```

3. Update the **server-side** env file so the api container picks up the new value
   (var name in `.env.prod` is `POSTGRES_PASSWORD`, mapped to `DATABASE_PASSWORD`
   in `docker-compose.prod.yml`). Edit `.env.prod` and set:

   ```
   POSTGRES_PASSWORD=<the new value>
   ```

4. Restart the api container so it reconnects with the new credential:

   ```bash
   docker compose -f docker-compose.prod.yml --env-file .env.prod up -d identity-core-api
   ```

5. Verify: `docker logs --tail=50 identity-core-api` shows a clean datasource /
   Flyway startup (no auth failures), and `/actuator/health` (or the app health
   endpoint) is UP.

> If the Postgres container itself reads `POSTGRES_PASSWORD` at init, the ALTER
> ROLE above is still the authority for the **already-initialized** volume — do not
> re-init the data volume. Keep the `.env.prod` value and the live role password in
> lockstep.

---

## (b) Rotate the Redis password

1. Generate a new password:

   ```bash
   NEWREDIS="$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-40)"
   ```

2. Set `requirepass` on the running Redis (and persist it to the config so it
   survives a restart). Either update the `redis.conf` / compose `requirepass`
   argument, or set it live then rewrite:

   ```bash
   # set live (old password may be needed to authenticate first if already set)
   docker exec -i shared-redis redis-cli CONFIG SET requirepass "$NEWREDIS"
   # persist to the running config file so a restart keeps it
   docker exec -i shared-redis redis-cli -a "$NEWREDIS" CONFIG REWRITE
   ```

   If Redis is started with `--requirepass ${REDIS_PASSWORD}` in
   `docker-compose.prod.yml`, update `.env.prod` (`REDIS_PASSWORD=<new value>`) so
   the **restart** uses the new password too.

3. Update the server-side env file used by the api (`.env.prod` →
   `REDIS_PASSWORD=<the new value>`; mapped to `REDIS_PASSWORD` in the api
   container).

4. Restart both the Redis container (to load the persisted/`--requirepass` value)
   and the api (to reconnect):

   ```bash
   docker compose -f docker-compose.prod.yml --env-file .env.prod up -d shared-redis identity-core-api
   ```

5. Verify: `docker exec -i shared-redis redis-cli -a "$NEWREDIS" PING` → `PONG`,
   and the api logs show Redis connectivity (no `NOAUTH` / auth errors). Note Redis
   backs MFA/approve-login/QR sessions, so a brief blip may drop in-flight MFA
   sessions — expected.

---

## (c) Regenerate the JWT secret

**WARNING — this invalidates ALL existing access tokens / sessions. Every user
must re-login.** Schedule for a low-traffic window and post a heads-up if needed.

1. Generate a new high-entropy secret (the prod profile fails fast on boot if the
   secret is too short/blank — use ample length):

   ```bash
   NEWJWT="$(openssl rand -base64 64 | tr -d '\n')"
   ```

2. Update the server-side env file (`.env.prod` → `JWT_SECRET=<the new value>`;
   mapped to `JWT_SECRET` in the api container). Keep `APP_SECURITY_JWT_AUDIENCE`
   non-blank (e.g. `fivucsas-api`) — leaving it blank crash-loops the prod profile.

3. Restart the api:

   ```bash
   docker compose -f docker-compose.prod.yml --env-file .env.prod up -d identity-core-api
   ```

4. Verify: api boots, `/actuator/health` UP, a fresh login mints a valid token, and
   any token minted under the old secret is now rejected (re-login required).

> **Lower-disruption alternative (HS key rotation, PR #64):** the service supports
> kid-routed HS secrets via `HsKeyRegistry`. Because the leaked `JWT_SECRET` maps to
> the legacy kid `hs-2026-04`, you can introduce a NEW active kid + secret and demote
> the leaked one to verify-only, then drop it after the access-token TTL elapses —
> rotating signing material WITHOUT a hard logout of everyone. If that registry path
> is wired in prod, prefer it; otherwise the hard rotation above is the fallback and
> is always correct. Either way, the leaked secret must stop being trusted.

---

## (d) History note — why rotation is the operative fix

The compromised values remain readable in git history at commit `f9f0f2d` on
`origin/main`. Truly **removing** them from history requires rewriting every commit
that contains the blob (`git filter-repo --invert-paths --path .env.hetzner`, or
BFG) **followed by a force-push to `main`**.

That force-push is **BLOCKED** in this environment:
- `git push --force*` is hard-denied, and
- direct pushes to the default branch (`main`/`master`) are hard-denied + protected
  by branch protection.

A history rewrite also breaks every existing clone/fork and is coordination-heavy.
**Therefore the secrets must be treated as permanently exposed, and ROTATION (steps
a–c) is the real remediation** — once rotated, the leaked values in history are
inert. The `.gitignore` hardening + `git rm --cached` on this branch prevents any
re-leak going forward.

### Optional follow-up (operator-driven, not blocking)
If leadership decides history must also be scrubbed, that is a separate, manually
coordinated operation requiring temporarily relaxing branch protection and an
explicit human-run force-push — out of scope for the autonomous workflow and
**not** a substitute for rotation.

---

## Checklist

- [ ] Postgres password rotated (ALTER ROLE) + `.env.prod` updated + api restarted + verified
- [ ] Redis password rotated (`requirepass` + CONFIG REWRITE) + `.env.prod` updated + restart + `PONG`
- [ ] `JWT_SECRET` regenerated + `.env.prod` updated + api restarted (all users re-login) + verified
- [ ] Old `.env.prod.bak.*` backups secured (`chmod 600`, never committed)
- [ ] Confirmed `.env.hetzner` is untracked + gitignored going forward
