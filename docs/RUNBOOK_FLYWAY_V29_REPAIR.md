# Runbook — Flyway repair after the V29/V40/V41 DR-safety edits

**Status:** REQUIRED before the next prod (and staging) boot that ships this change.
**Owner action.** Do NOT skip — `spring.flyway.validate-on-migrate=true` in prod
(`application-prod.yml`, enforced since 2026-05-11) will otherwise crash-loop the
app on boot with a checksum-mismatch on V29, V40, and V41.

## Why a repair is needed

P1-5 (disaster-recovery safety) required making the Flyway chain apply cleanly from
a **fresh** database. Three already-applied migrations were edited:

| Version | File | Edit | Runtime effect on prod |
|---|---|---|---|
| V29 | `V29__add_email_otp_to_default_login_flow.sql` | Resolve the system "Default Login" flow + EMAIL_OTP method by **natural key** instead of two hardcoded prod-only UUIDs; keep the idempotent `WHERE NOT EXISTS (step_order = 2)` guard. | **None.** The step_order=2 row already exists on prod, so 0 rows are written (verified by a ROLLBACK transaction against prod). |
| V40 | `V40__partition_audit_logs.sql` | (a) Rename the legacy PK index `audit_logs_pkey` → `audit_logs_legacy_pkey` (one `ALTER INDEX IF EXISTS`) so the new composite PK can be created on a from-zero run. (b) Fix the trailing `COMMENT ON TABLE … IS 'a' \|\| 'b'` (a SQL syntax error) to a single string literal. | **None.** V40 is already `success=t` and never re-executes; the rename only fires inside V40's own from-scratch run. Prod's `audit_logs_pkey` is owned by the partitioned root, not a legacy table, so the rename would be a no-op there anyway. |
| V41 | `V41__audit_logs_partition_maintenance.sql` | Fix the same invalid `COMMENT … IS 'a' \|\| 'b'` concatenation to a single literal. | **None.** Already `success=t`; never re-executes. |

These edits change the **checksums** Flyway computes for V29/V40/V41. On a DB that
already applied them, `validate-on-migrate` compares the new file checksum to the
stored one and fails. `flyway repair` re-stamps the stored checksums to match the
edited files **without re-running any migration** (descriptions and versions are
unchanged, so nothing else in the history row moves).

> Note: V40 and V41 contained a `COMMENT … IS 'a' || 'b'` concatenation that is a
> PostgreSQL **syntax error** — i.e. the committed text never actually executed on
> any database (prod's `audit_logs` comment is still the old V5 text). Prod's V40/V41
> rows are nonetheless `success=t`, so prod's live schema is correct and untouched;
> the repair only reconciles the stored checksums with the now-valid files.

## Prod checksums BEFORE the repair (for reference / rollback)

```
version | description                         | checksum (pre-edit, stored in prod)
--------+-------------------------------------+------------------------------------
   29   | add email otp to default login flow | -1799823743
   40   | partition audit logs                |  1442904668
   41   | audit logs partition maintenance    | -1174003222
```

After the repair these three rows hold the checksums of the **edited** files.

## Procedure (prod)

Run this AFTER pulling the new image but BEFORE/INSTEAD of letting the app run
`validate`. There is no Flyway CLI on the VPS — use the one-shot container that
ships with the app image, or run `repair` via the app with validate temporarily
relaxed. Two equivalent options:

### Option A — one-time relaxed-validate boot (simplest, no extra tooling)

```bash
cd /opt/projects/fivucsas/identity-core-api
# 1. Temporarily relax validation so the app can boot and run `repair`-equivalent.
#    Spring Boot's Flyway auto-config calls migrate(); with validate-on-migrate=false
#    it will re-stamp on the next migrate without failing on the checksum diff IS NOT
#    automatic — so use the explicit repair in Option B. Prefer Option B.
```

> Spring's `migrate()` does **not** auto-repair a checksum mismatch even with
> `validate-on-migrate=false` — it just skips validation. To actually re-stamp the
> stored checksums, run an explicit `flyway repair`. Use Option B.

### Option B — explicit `flyway repair` (recommended)

Run the Flyway image against prod's DB on the Docker network (`shared-postgres`),
pointing at the **edited** migration files from the new image/checkout:

```bash
cd /opt/projects/fivucsas/identity-core-api

# Sanity: show the mismatched rows first (optional)
docker exec shared-postgres psql -U postgres -d identity_core \
  -c "SELECT version, description, checksum FROM flyway_schema_history WHERE version IN ('29','40','41') ORDER BY version::int;"

# Repair: re-stamp stored checksums from the migration files in this checkout.
# (Use the same DB creds as .env.prod; identity_core DB on shared-postgres.)
docker run --rm \
  --network <fivucsas_network> \
  -v "$PWD/src/main/resources/db/migration:/flyway/sql:ro" \
  flyway/flyway:10 \
  -url="jdbc:postgresql://shared-postgres:5432/identity_core" \
  -user="$DB_USERNAME" -password="$DB_PASSWORD" \
  -baselineOnMigrate=true -baselineVersion=0 \
  repair

# Verify the three checksums now match the edited files, then deploy/boot normally.
```

> `<fivucsas_network>` = the compose network `shared-postgres` is attached to
> (find via `docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' shared-postgres`).
> `flyway repair` ONLY: (1) re-stamps checksums of applied migrations to match the
> files, and (2) removes failed-migration rows. It runs **no** DDL/DML.

### After repair — normal deploy

```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod build --no-cache identity-core-api
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d identity-core-api
# App boots; Flyway validate passes (checksums match); migrate is a no-op (already at head).
curl -s http://127.0.0.1:8080/actuator/health
```

## Staging

The staging DB is cloned from prod (see `RUNBOOK_STAGING.md`), so its
`flyway_schema_history` carries the **same** pre-edit V29/V40/V41 checksums and needs
the identical `repair` (point the same command at `identity_core_staging`) before
the staging container runs the new image. Going forward, once this DR fix is in,
staging *could* be migrated from scratch instead of cloned — see the verification note.

## Verification performed (2026-05-30)

- **BEFORE:** a from-zero psql replay of V0..V71 failed at
  `V29` → `auth_flow_steps_auth_flow_id_fkey` on key `e986943a-…` (the exact DR
  symptom). Also latent: V40 PK-index collision and the V40/V41 invalid-COMMENT
  syntax errors.
- **AFTER:** the full V0..V71 chain applied on a throwaway `flyway_dr_test` DB
  (`CREATE EXTENSION vector`) with **zero errors**; the system "Default Login" flow
  ends with PASSWORD(1)+EMAIL_OTP(2, required, 300s, 3 attempts) — byte-identical to
  prod's row — and `audit_logs` is range-partitioned. Throwaway DB dropped after.
- **Prod no-op:** the rewritten V29 body run inside a `BEGIN … ROLLBACK` against the
  live `identity_core` DB inserted **0 rows**.
