# Runbook — Unused-Index Audit (7-day window)

## Purpose

Identify and drop indexes that nobody scans, to reclaim write-overhead and
disk on `identity_core`. PostgreSQL ships `pg_stat_user_indexes` which
exposes `idx_scan` (number of times each index has been used as a scan
target). An index with `idx_scan = 0` over a representative window is a
strong drop candidate.

The trap is that `idx_scan` is cumulative since the last stats reset (often:
postgres process start, which on this host is months ago). A value of `1`
could mean "used once last week" or "used once in 2024 and never since". So
we explicitly reset and observe for a fixed window.

## Window

- **Kick-off date**: 2026-05-11
- **Re-check date**: 2026-05-18 (T+7d)

T+7d is the minimum useful window: one full business-week of traffic +
the daily soft-delete-purge job + the weekly stats / disk-guard / aggressive
prune cron jobs (see `/opt/projects/infra/RUNBOOK_DISK.md`).

## Step 1 — Reset counters (kick-off)

Run from the Hetzner host on 2026-05-11:

```bash
cd /opt/projects/fivucsas/identity-core-api
./scripts/db/reset-pg-stat-user-indexes.sh
```

The script narrowly resets per-index counters in the `public` schema only —
table-level seq/idx counters used by other dashboards are untouched.

DO NOT run this from the V60 PR. The script + this runbook is the
deliverable; the operator runs the reset. Resetting from a deploy hook
would silently re-arm the window mid-audit.

## Step 2 — Observe (T+0d to T+7d)

Normal traffic runs against the now-reset counters. No action needed.

## Step 3 — Re-check (T+7d, 2026-05-18)

```bash
docker exec fivucsas-postgres psql -U postgres -d identity_core -c "
  SELECT schemaname, relname, indexrelname, idx_scan, pg_size_pretty(pg_relation_size(indexrelid)) AS size
    FROM pg_stat_user_indexes
   WHERE idx_scan = 0
     AND schemaname = 'public'
   ORDER BY pg_relation_size(indexrelid) DESC;
"
```

Record the output in `INFRA_REVIEW_DEVOPS_2026-XX-XX.md` (or wherever the
follow-up DB review lands) — it becomes the canonical "drop candidate" list.

## Step 4 — Apply drop criteria

An index is a safe drop only if ALL of:

1. `idx_scan = 0` in the 7-day window.
2. NOT a primary key (`indisprimary = true` filter the row out).
3. NOT a uniqueness-enforcing index that protects a critical invariant
   (e.g. `webauthn_credentials.credential_id` MUST stay unique even if no
   query ever scans by it).
4. NOT a partial-index on a rarely-hit branch (idx_scan = 0 for a week is
   expected on a fire-rarely query path; check `indpred` in `pg_index` and
   correlate with code).
5. NOT on any of the following tables — they have rare-but-critical access
   paths that the 7-day window cannot characterize fully:
   - `webauthn_credentials` (login-time only, low-traffic tenants may not
     hit every credential type in a week)
   - `oauth2_clients` (client-credentials flow is bursty per integration
     partner)
   - `refresh_tokens` (rotation chains can sit idle for the full TTL)
   - `audit_logs` (range-partitioned by V40/V57; per-partition indexes
     look idle until the corresponding date-range partition is hit by a
     tenant-admin query)

Drops are issued as a new Flyway migration (`V6X__drop_unused_indexes.sql`),
NOT ad-hoc `DROP INDEX` over psql. The migration is the audit trail.

## Step 5 — Validate post-drop

After the drop migration applies in prod:

```bash
docker exec fivucsas-postgres psql -U postgres -d identity_core -c "
  SELECT count(*) FROM pg_indexes WHERE schemaname = 'public';
"
```

Diff against the pre-drop count and confirm the difference matches the
number of indexes the migration removed. Then re-run Step 1 to start the
next audit window — the goal is to drive `idx_scan = 0` indexes toward zero
over successive 7-day cycles.

## Cross-references

- `scripts/db/reset-pg-stat-user-indexes.sh` — the one-shot reset script
- `SENIOR_DB_REVIEW_2026-05-04.md` §Appendix C (or the most recent DB
  review on disk) — surfaced this audit as a follow-up from the
  audit_logs.tenant_id backfill work
- `/opt/projects/infra/RUNBOOK_DISK.md` — disk-capacity defence layers
  that overlap with the index-bloat reclamation goal
