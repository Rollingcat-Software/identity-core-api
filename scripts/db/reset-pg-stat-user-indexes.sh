#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# reset-pg-stat-user-indexes.sh
#
# One-shot reset of PostgreSQL per-index statistics in the public schema. The
# reset clears idx_scan / idx_tup_read counters so a fresh 7-day audit window
# can identify truly-unused indexes (idx_scan = 0) for safe drop.
#
# Why: pg_stat_user_indexes is cumulative since the server's last stats reset
# (often: process start). Without an explicit reset we can't tell whether an
# index with idx_scan = 1 is actually used (one scan in the past month) or
# unused (one scan two years ago, never since). Periodically resetting and
# observing for a fixed window gives an actionable signal.
#
# Operator runbook for the wider audit lives in
# docs/RUNBOOK_UNUSED_INDEX_AUDIT.md.
#
# Usage:
#   ./scripts/db/reset-pg-stat-user-indexes.sh
#
# Prereqs:
#   * Run on the Hetzner host (or anywhere `docker exec` reaches the
#     `fivucsas-postgres` container).
#   * Caller must own the affected tables. The container's `postgres`
#     superuser does — for least-privilege deployments adjust the -U flag.
#
# Idempotency: safe to re-run. Each call resets the counters back to zero.
# ---------------------------------------------------------------------------
set -euo pipefail

CONTAINER="${POSTGRES_CONTAINER:-fivucsas-postgres}"
DB="${POSTGRES_DB:-identity_core}"
USER="${POSTGRES_USER:-postgres}"

echo "Resetting per-index stats for ${CONTAINER}.${DB} (public schema)..."

# pg_stat_reset_single_table_counters() works on both tables and indexes
# (relkind = 'r' or 'i'). We narrow to indexes only so the table-level
# scan/seq/idx counters used by other dashboards stay intact.
docker exec "${CONTAINER}" psql -U "${USER}" -d "${DB}" -c "
  SELECT pg_stat_reset_single_table_counters(c.oid)
    FROM pg_class c
    JOIN pg_namespace n ON c.relnamespace = n.oid
   WHERE n.nspname = 'public'
     AND c.relkind = 'i';
"

echo "Done. The 7-day audit window starts now."
echo "Re-check command:"
echo "  docker exec ${CONTAINER} psql -U ${USER} -d ${DB} -c \\"
echo "    \"SELECT schemaname, relname, indexrelname, idx_scan FROM pg_stat_user_indexes WHERE idx_scan = 0 ORDER BY relname, indexrelname;\""
