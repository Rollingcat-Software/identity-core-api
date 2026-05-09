-- V40: Range-partition audit_logs by created_at (monthly)
-- ---------------------------------------------------------------------------
-- Addresses AUDIT_2026-04-19 finding IN-H5: audit_logs was unpartitioned and
-- growing unbounded, making retention/archival and per-period scans expensive.
--
-- Strategy (approach "a" — no pg_partman dependency):
--   1. Rename existing audit_logs → audit_logs_legacy.
--   2. Create a new audit_logs partitioned BY RANGE (created_at), cloning the
--      legacy schema (INCLUDING ALL copies defaults, constraints, indexes,
--      storage, comments, generated/identity settings).
--   3. Pre-create monthly partitions from 2026-01-01 through 2026-07-01
--      (6 months; at least 2 months ahead of today 2026-04-20 to avoid the
--      "no partition of relation audit_logs found for row" runtime error).
--   4. ATTACH audit_logs_legacy as a historical partition covering
--      [least(min(created_at), MINVALUE-equivalent), 2026-01-01).
--
-- IMPORTANT: requires a maintenance window.
--   - Takes ACCESS EXCLUSIVE lock on audit_logs during RENAME.
--   - Partitioned-table PK MUST include the partition key (`created_at`).
--     V5 defined PK as `id` alone; this migration changes it semantically to
--     (id, created_at). Application code treats `id` as the logical key and
--     never joins on PK, so the app contract is unaffected, but DBAs must be
--     aware that `id` alone is no longer a unique constraint at the root.
--   - RLS policies from V25 apply to the root partitioned table; inherited
--     automatically on partitions from PG 11+ but we re-enable explicitly.
--   - Views/triggers/functions defined on V8 referencing audit_logs remain
--     valid because they reference the table name, which now points at the
--     partitioned root. The V8 BEFORE INSERT trigger must be re-attached to
--     the new root (partitioned tables require row triggers on each
--     partition — we rely on the new parent-level trigger semantics
--     available since PG 13 by attaching to the parent).
--
-- NOT RUN AUTOMATICALLY IN CI. Deploy during a maintenance window.
-- ---------------------------------------------------------------------------

BEGIN;

-- Safety: abort if the legacy table already exists (re-run guard).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'audit_logs_legacy') THEN
        RAISE EXCEPTION 'audit_logs_legacy already exists — V40 appears partially applied. Aborting.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'audit_logs' AND relkind = 'r') THEN
        RAISE EXCEPTION 'audit_logs is not a plain table (relkind <> r). Already partitioned? Aborting.';
    END IF;
END $$;

-- Drop dependent views/triggers that would block rename / cloning.
-- They are recreated at the end pointing at the new partitioned root.
DROP VIEW IF EXISTS v_recent_audit_logs;
DROP VIEW IF EXISTS v_slow_operations;
DROP MATERIALIZED VIEW IF EXISTS mv_audit_statistics;
DROP TRIGGER IF EXISTS trg_populate_audit_request_id ON audit_logs;

-- Step 1: rename existing table.
ALTER TABLE audit_logs RENAME TO audit_logs_legacy;

-- Rename the legacy primary-key constraint so it doesn't clash with the
-- composite PK we ADD on the new partitioned root below. Postgres carries
-- the constraint name across RENAME TABLE — without this, the later
-- `ADD CONSTRAINT audit_logs_pkey` errors with "relation already exists".
-- Idempotent: the constraint is named `audit_logs_pkey` only when the
-- original V5 created it that way; some installs (where the original PK
-- was declared inline as `id UUID PRIMARY KEY`) auto-named it that way too.
DO $rename_legacy_pkey$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'audit_logs_pkey'
          AND conrelid = 'audit_logs_legacy'::regclass
    ) THEN
        ALTER TABLE audit_logs_legacy
            RENAME CONSTRAINT audit_logs_pkey TO audit_logs_legacy_pkey;
    END IF;
END $rename_legacy_pkey$;

-- Rename old indexes so they don't clash with the clones we're about to make.
-- (INCLUDING ALL below would try to create indexes with identical names.)
ALTER INDEX IF EXISTS idx_audit_tenant RENAME TO idx_audit_legacy_tenant;
ALTER INDEX IF EXISTS idx_audit_user RENAME TO idx_audit_legacy_user;
ALTER INDEX IF EXISTS idx_audit_action RENAME TO idx_audit_legacy_action;
ALTER INDEX IF EXISTS idx_audit_resource RENAME TO idx_audit_legacy_resource;
ALTER INDEX IF EXISTS idx_audit_created_at RENAME TO idx_audit_legacy_created_at;
ALTER INDEX IF EXISTS idx_audit_success RENAME TO idx_audit_legacy_success;
ALTER INDEX IF EXISTS idx_audit_request_id RENAME TO idx_audit_legacy_request_id;
ALTER INDEX IF EXISTS idx_audit_duration_slow RENAME TO idx_audit_legacy_duration_slow;
ALTER INDEX IF EXISTS idx_audit_request_timing RENAME TO idx_audit_legacy_request_timing;
ALTER INDEX IF EXISTS idx_audit_enhanced_metadata_gin RENAME TO idx_audit_legacy_enhanced_metadata_gin;
ALTER INDEX IF EXISTS idx_audit_retention RENAME TO idx_audit_legacy_retention;
ALTER INDEX IF EXISTS idx_audit_tenant_created RENAME TO idx_audit_legacy_tenant_created;
ALTER INDEX IF EXISTS idx_audit_user_action_created RENAME TO idx_audit_legacy_user_action_created;
ALTER INDEX IF EXISTS idx_audit_tenant_action_created RENAME TO idx_audit_legacy_tenant_action_created;

-- Step 2: create the new partitioned root.
-- LIKE ... INCLUDING ALL copies columns, defaults, constraints, comments,
-- storage, and identity. We deliberately EXCLUDE the primary key from LIKE
-- (because the legacy PK is (id) alone — invalid for a table partitioned by
-- created_at) and add a composite PK explicitly after creation.
CREATE TABLE audit_logs (
    LIKE audit_logs_legacy INCLUDING DEFAULTS
                           INCLUDING CONSTRAINTS
                           INCLUDING COMMENTS
                           INCLUDING STORAGE
) PARTITION BY RANGE (created_at);

-- Composite primary key (required for partitioned tables).
-- Semantic change from V5: `id` alone is no longer a unique constraint at the
-- root. Application code treats id as the logical row identifier.
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id, created_at);

-- Re-create indexes on the partitioned root. Postgres propagates these to
-- every existing and future partition automatically.
CREATE INDEX idx_audit_tenant             ON audit_logs (tenant_id);
CREATE INDEX idx_audit_user               ON audit_logs (user_id);
CREATE INDEX idx_audit_action             ON audit_logs (action);
CREATE INDEX idx_audit_resource           ON audit_logs (resource_type, resource_id);
CREATE INDEX idx_audit_created_at         ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_success            ON audit_logs (success);
CREATE INDEX idx_audit_tenant_created     ON audit_logs (tenant_id, created_at DESC);
CREATE INDEX idx_audit_user_action_created ON audit_logs (user_id, action, created_at DESC);
CREATE INDEX idx_audit_tenant_action_created ON audit_logs (tenant_id, action, created_at DESC);
CREATE INDEX idx_audit_request_id         ON audit_logs (request_id) WHERE request_id IS NOT NULL;
CREATE INDEX idx_audit_duration_slow      ON audit_logs (duration_ms DESC, created_at DESC) WHERE duration_ms > 1000;
CREATE INDEX idx_audit_request_timing     ON audit_logs (request_id, created_at, duration_ms) WHERE request_id IS NOT NULL;
CREATE INDEX idx_audit_enhanced_metadata_gin ON audit_logs USING GIN (enhanced_metadata) WHERE enhanced_metadata IS NOT NULL AND enhanced_metadata != '{}'::jsonb;
CREATE INDEX idx_audit_retention          ON audit_logs (created_at);

-- Step 3: pre-create monthly partitions from 2026-01-01 through 2026-07-01.
-- We create 2026-01..2026-06 explicitly so writes for the current month
-- (2026-04) and the next two months (2026-05, 2026-06) don't fail.
CREATE TABLE audit_logs_2026_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE audit_logs_2026_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE audit_logs_2026_03 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE audit_logs_2026_04 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE audit_logs_2026_05 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_logs_2026_06 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

-- Step 4: attach legacy as a historical partition.
-- Bound computed from legacy min(created_at). Upper bound is 2026-01-01 so
-- the legacy partition covers everything strictly before the first monthly
-- partition. We require ALL legacy rows to satisfy created_at < 2026-01-01;
-- if any rows are newer we move them into the monthly partitions before
-- attaching (this is a non-data-destructive redistribution).
DO $$
DECLARE
    legacy_min timestamp;
    legacy_max timestamp;
    lower_bound timestamp;
BEGIN
    SELECT MIN(created_at), MAX(created_at)
      INTO legacy_min, legacy_max
      FROM audit_logs_legacy;

    IF legacy_min IS NULL THEN
        -- empty legacy table; use a safe sentinel lower bound
        lower_bound := TIMESTAMP '2000-01-01';
    ELSE
        -- Round min down to the first day of its month for a clean boundary.
        lower_bound := date_trunc('month', legacy_min);
    END IF;

    -- Relocate any legacy rows >= 2026-01-01 into the new partitioned table
    -- (they would otherwise violate the attach constraint).
    IF legacy_max IS NOT NULL AND legacy_max >= TIMESTAMP '2026-01-01' THEN
        INSERT INTO audit_logs
        SELECT * FROM audit_logs_legacy WHERE created_at >= TIMESTAMP '2026-01-01';
        DELETE FROM audit_logs_legacy WHERE created_at >= TIMESTAMP '2026-01-01';
        RAISE NOTICE 'Relocated audit_logs_legacy rows >= 2026-01-01 into monthly partitions.';
    END IF;

    -- If legacy is now empty (all rows were recent and got relocated) OR was
    -- empty to begin with with all lower_bound >= 2026-01-01, there is no
    -- historical data worth preserving. Drop the rename'd table and skip
    -- the ATTACH. Partition bound "FROM (2026-04-01) TO (2026-01-01)" would
    -- be an empty range, which Postgres rejects with:
    --     ERROR: empty range bound specified for partition
    IF NOT EXISTS (SELECT 1 FROM audit_logs_legacy LIMIT 1) THEN
        RAISE NOTICE 'audit_logs_legacy is empty after relocation — dropping instead of attaching.';
        DROP TABLE audit_logs_legacy;
        RETURN;
    END IF;

    -- Safety: if after relocation the lower_bound is still >= 2026-01-01
    -- (can happen if legacy had only post-2026 rows that were relocated but
    -- the sentinel was never reset), fall back to the epoch-safe bound.
    IF lower_bound >= TIMESTAMP '2026-01-01' THEN
        lower_bound := TIMESTAMP '2000-01-01';
    END IF;

    -- Add a CHECK constraint matching the partition bound to skip the full
    -- table scan during ATTACH (PG optimization).
    EXECUTE format(
        'ALTER TABLE audit_logs_legacy ADD CONSTRAINT audit_logs_legacy_range_check '
        || 'CHECK (created_at >= %L AND created_at < %L) NOT VALID',
        lower_bound, TIMESTAMP '2026-01-01');
    EXECUTE 'ALTER TABLE audit_logs_legacy VALIDATE CONSTRAINT audit_logs_legacy_range_check';

    EXECUTE format(
        'ALTER TABLE audit_logs ATTACH PARTITION audit_logs_legacy '
        || 'FOR VALUES FROM (%L) TO (%L)',
        lower_bound, TIMESTAMP '2026-01-01');

    RAISE NOTICE 'Attached audit_logs_legacy as partition [% , 2026-01-01).', lower_bound;
END $$;

-- Re-attach the V8 trigger to the new root.
CREATE TRIGGER trg_populate_audit_request_id
    BEFORE INSERT ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION populate_audit_request_id();

COMMENT ON TRIGGER trg_populate_audit_request_id ON audit_logs IS
    'Automatically extracts request_id and duration from metadata for indexing';

-- Re-enable RLS (inherited to partitions automatically, but re-declared for clarity).
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Re-create V25 RLS policies on the new root.
-- (Legacy policies attached to audit_logs_legacy survive the rename; the
-- child table inherits no RLS from root, so legacy partition needs its own.
-- Partitioned-root policies apply to the partition view; explicit policies on
-- audit_logs_legacy remain from V25 so historical reads are still guarded.)
DROP POLICY IF EXISTS audit_logs_tenant_isolation ON audit_logs;
DROP POLICY IF EXISTS audit_logs_tenant_insert ON audit_logs;

CREATE POLICY audit_logs_tenant_isolation ON audit_logs
    FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

CREATE POLICY audit_logs_tenant_insert ON audit_logs
    FOR INSERT
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));

COMMENT ON POLICY audit_logs_tenant_isolation ON audit_logs IS
    'RLS: Restrict audit log access to current tenant (re-declared in V40)';

-- Recreate views and materialized view.
CREATE OR REPLACE VIEW v_recent_audit_logs AS
SELECT id, tenant_id, user_id, action, resource_type, resource_id,
       http_method, endpoint, status_code, success, error_message,
       ip_address, user_agent, user_agent_v2, request_id, duration_ms,
       created_at,
       COALESCE(enhanced_metadata, '{}'::jsonb) || COALESCE(metadata, '{}'::jsonb) AS combined_metadata
FROM audit_logs
WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
ORDER BY created_at DESC;

COMMENT ON VIEW v_recent_audit_logs IS 'Recent audit logs (30 days) for fast access and monitoring';

CREATE OR REPLACE VIEW v_slow_operations AS
SELECT id, tenant_id, user_id, action, resource_type, endpoint,
       duration_ms, created_at, request_id
FROM audit_logs
WHERE duration_ms > 1000
  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY duration_ms DESC;

COMMENT ON VIEW v_slow_operations IS 'Operations exceeding 1 second in the last 7 days for performance analysis';

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_audit_statistics AS
SELECT tenant_id, action, resource_type, DATE(created_at) AS audit_date,
       COUNT(*) AS total_operations,
       COUNT(*) FILTER (WHERE success = TRUE) AS successful_operations,
       COUNT(*) FILTER (WHERE success = FALSE) AS failed_operations,
       AVG(duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS avg_duration_ms,
       MAX(duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS max_duration_ms,
       MIN(created_at) AS first_operation_at,
       MAX(created_at) AS last_operation_at
FROM audit_logs
WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY tenant_id, action, resource_type, DATE(created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_audit_stats_unique
    ON mv_audit_statistics (tenant_id, action, resource_type, audit_date);
CREATE INDEX IF NOT EXISTS idx_mv_audit_stats_date
    ON mv_audit_statistics (audit_date DESC);

COMMENT ON MATERIALIZED VIEW mv_audit_statistics IS
    'Pre-aggregated audit statistics for analytics dashboards (refresh daily)';

COMMENT ON TABLE audit_logs IS
    'Range-partitioned by created_at (monthly). Pre-created partitions: 2026-01..2026-06 plus audit_logs_legacy covering pre-2026-01. '
    || 'Schedule ensure_audit_logs_partition() monthly (see V41) to create the next month partition at least 2 months ahead. '
    || 'PK is (id, created_at) — semantic change from V5 where PK was (id) alone. IN-H5 (AUDIT_2026-04-19).';

COMMIT;
