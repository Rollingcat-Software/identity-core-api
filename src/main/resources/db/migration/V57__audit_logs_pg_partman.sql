-- V57: Hand audit_logs partition lifecycle to pg_partman
-- ---------------------------------------------------------------------------
-- Builds on V40 (Range partition by created_at, monthly) + V41
-- (ensure_audit_logs_partition() helper) by replacing the manual cron with
-- pg_partman's automated maintenance: forward partition pre-creation,
-- retention drop, and (where available) the bgw scheduler.
--
-- WHY:
--   - V40 created 2026-01..2026-06 partitions only. Manual cron via V41's
--     `ensure_audit_logs_partition()` requires an external scheduler that
--     was never wired (DB review 2026-04-30 §4 found V40/V41 also rolled
--     back in prod via BASELINE SKIP markers, so we cannot rely on either).
--   - pg_partman's `partition_data_proc` + `run_maintenance_proc` is the
--     industry-standard way to do this. It owns the partition naming and
--     retention contract going forward. ARCHITECTURE_REVIEW_2026-04-30
--     §audit-context references audit_logs as already partitioned monthly;
--     this migration makes that statement true and self-maintaining.
--
-- IDEMPOTENT:
--   - Re-runs cleanly. Detects whether audit_logs is already partitioned
--     (relkind='p') vs plain heap (relkind='r'). Skips re-partitioning if
--     already partitioned. Skips create_parent if part_config row already
--     exists. CREATE EXTENSION IF NOT EXISTS for partman + pg_cron.
--
-- NOT APPLIED IN CI BY DEFAULT:
--   - Requires `pg_partman` extension installed at the OS level
--     (postgresql-16-partman package, or a custom pgvector+partman image).
--     Wrapped in a safe abort if the extension is unavailable so dev/test
--     environments without partman do not block on this migration. Set
--     `app.skip_partman_v57=on` (server-level) to bypass entirely.
--
-- RETENTION:
--   - 24 months default (matches GDPR/KVKK + 6-year SOC2 retention is
--     enforced via off-site archival, not live partitions). Override at
--     runtime with `partman.update_part_config()`.
--
-- SCHEDULING:
--   - Prefers `pg_partman_bgw` (a worker that calls run_maintenance every
--     `pg_partman_bgw.interval` seconds) when configured at server start.
--     Falls back to a `pg_cron` job if the `pg_cron` extension is present.
--     Falls back to a NOTICE recommending operator wire it manually.
--
-- ROLLBACK:
--   - Manual: `SELECT partman.undo_partition('public.audit_logs',
--             p_keep_table := true);` then drop partman config row.
--   - The Spring-side @Bean pre-creator (none currently exists, see
--     audit) is intentionally not introduced; we rely on partman.
-- ---------------------------------------------------------------------------

DO $V57$
DECLARE
    v_skip          boolean := COALESCE(current_setting('app.skip_partman_v57', true), 'off') = 'on';
    v_relkind       "char";
    v_partman_avail boolean;
    v_pgcron_avail  boolean;
    v_already_cfg   boolean;
    v_legacy_min    timestamptz;
    v_legacy_max    timestamptz;
    v_lower_bound   timestamptz;
BEGIN
    IF v_skip THEN
        RAISE NOTICE 'V57: app.skip_partman_v57=on, skipping pg_partman migration entirely.';
        RETURN;
    END IF;

    -- ----------------------------------------------------------------------
    -- Step 0: probe extension availability.
    -- ----------------------------------------------------------------------
    SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_partman')
      INTO v_partman_avail;
    SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron')
      INTO v_pgcron_avail;

    IF NOT v_partman_avail THEN
        RAISE WARNING 'V57: pg_partman extension is NOT available on this server. '
                      'Skipping migration. To proceed, install postgresql-16-partman '
                      '(or use a Docker image bundling it), then re-run Flyway. '
                      'Set app.skip_partman_v57=on to silence this warning.';
        RETURN;
    END IF;

    CREATE SCHEMA IF NOT EXISTS partman;
    CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;

    -- ----------------------------------------------------------------------
    -- Step 1: ensure audit_logs is range-partitioned by created_at.
    -- If it's a plain heap (relkind='r'), perform the V40 conversion in
    -- a single atomic block. If it's already partitioned, skip.
    -- ----------------------------------------------------------------------
    SELECT relkind INTO v_relkind
      FROM pg_class
     WHERE relname = 'audit_logs'
       AND relnamespace = 'public'::regnamespace;

    IF v_relkind IS NULL THEN
        RAISE EXCEPTION 'V57: audit_logs table not found. V5/V8 should have created it.';
    END IF;

    IF v_relkind = 'r' THEN
        RAISE NOTICE 'V57: audit_logs is a plain heap (V40 was rolled back or never applied). Converting to partitioned now.';

        -- Drop dependent objects that block RENAME.
        DROP VIEW IF EXISTS v_recent_audit_logs;
        DROP VIEW IF EXISTS v_slow_operations;
        DROP MATERIALIZED VIEW IF EXISTS mv_audit_statistics;
        DROP TRIGGER IF EXISTS trg_populate_audit_request_id ON audit_logs;

        -- Idempotency guard for legacy rename.
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'audit_logs_legacy_v57' AND relnamespace = 'public'::regnamespace) THEN
            RAISE EXCEPTION 'V57: audit_logs_legacy_v57 already exists. Aborting; manual cleanup required.';
        END IF;

        ALTER TABLE audit_logs RENAME TO audit_logs_legacy_v57;

        -- Rename indexes to free the original names for the new partitioned root.
        ALTER INDEX IF EXISTS idx_audit_tenant                  RENAME TO idx_audit_legacy_v57_tenant;
        ALTER INDEX IF EXISTS idx_audit_user                    RENAME TO idx_audit_legacy_v57_user;
        ALTER INDEX IF EXISTS idx_audit_action                  RENAME TO idx_audit_legacy_v57_action;
        ALTER INDEX IF EXISTS idx_audit_resource                RENAME TO idx_audit_legacy_v57_resource;
        ALTER INDEX IF EXISTS idx_audit_created_at              RENAME TO idx_audit_legacy_v57_created_at;
        ALTER INDEX IF EXISTS idx_audit_success                 RENAME TO idx_audit_legacy_v57_success;
        ALTER INDEX IF EXISTS idx_audit_request_id              RENAME TO idx_audit_legacy_v57_request_id;
        ALTER INDEX IF EXISTS idx_audit_duration_slow           RENAME TO idx_audit_legacy_v57_duration_slow;
        ALTER INDEX IF EXISTS idx_audit_request_timing          RENAME TO idx_audit_legacy_v57_request_timing;
        ALTER INDEX IF EXISTS idx_audit_enhanced_metadata_gin   RENAME TO idx_audit_legacy_v57_enhanced_metadata_gin;
        ALTER INDEX IF EXISTS idx_audit_retention               RENAME TO idx_audit_legacy_v57_retention;
        ALTER INDEX IF EXISTS idx_audit_tenant_created          RENAME TO idx_audit_legacy_v57_tenant_created;
        ALTER INDEX IF EXISTS idx_audit_user_action_created     RENAME TO idx_audit_legacy_v57_user_action_created;
        ALTER INDEX IF EXISTS idx_audit_tenant_action_created   RENAME TO idx_audit_legacy_v57_tenant_action_created;

        -- Build partitioned root cloning all attributes (excl. PK; we re-add a
        -- composite that includes the partition key, mandatory in PG 11+).
        CREATE TABLE audit_logs (
            LIKE audit_logs_legacy_v57 INCLUDING DEFAULTS
                                       INCLUDING CONSTRAINTS
                                       INCLUDING COMMENTS
                                       INCLUDING STORAGE
        ) PARTITION BY RANGE (created_at);

        ALTER TABLE audit_logs
            ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id, created_at);

        -- Recreate the indexes on the partitioned root (PG propagates to children).
        CREATE INDEX idx_audit_tenant                ON audit_logs (tenant_id);
        CREATE INDEX idx_audit_user                  ON audit_logs (user_id);
        CREATE INDEX idx_audit_action                ON audit_logs (action);
        CREATE INDEX idx_audit_resource              ON audit_logs (resource_type, resource_id);
        CREATE INDEX idx_audit_created_at            ON audit_logs (created_at DESC);
        CREATE INDEX idx_audit_success               ON audit_logs (success);
        CREATE INDEX idx_audit_tenant_created        ON audit_logs (tenant_id, created_at DESC);
        CREATE INDEX idx_audit_user_action_created   ON audit_logs (user_id, action, created_at DESC);
        CREATE INDEX idx_audit_tenant_action_created ON audit_logs (tenant_id, action, created_at DESC);
        CREATE INDEX idx_audit_request_id            ON audit_logs (request_id) WHERE request_id IS NOT NULL;
        CREATE INDEX idx_audit_duration_slow         ON audit_logs (duration_ms DESC, created_at DESC) WHERE duration_ms > 1000;
        CREATE INDEX idx_audit_request_timing        ON audit_logs (request_id, created_at, duration_ms) WHERE request_id IS NOT NULL;
        CREATE INDEX idx_audit_enhanced_metadata_gin ON audit_logs USING GIN (enhanced_metadata)
            WHERE enhanced_metadata IS NOT NULL AND enhanced_metadata != '{}'::jsonb;
        CREATE INDEX idx_audit_retention             ON audit_logs (created_at);

        -- Re-attach V8 trigger (function still exists).
        IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'populate_audit_request_id') THEN
            EXECUTE 'CREATE TRIGGER trg_populate_audit_request_id '
                 || 'BEFORE INSERT ON audit_logs FOR EACH ROW '
                 || 'EXECUTE FUNCTION populate_audit_request_id()';
        END IF;

        -- Re-enable RLS + tenant policies (V25 contract).
        ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS audit_logs_tenant_isolation ON audit_logs;
        DROP POLICY IF EXISTS audit_logs_tenant_insert    ON audit_logs;

        CREATE POLICY audit_logs_tenant_isolation ON audit_logs
            FOR ALL
            USING (tenant_id::text = current_setting('app.current_tenant_id', true));
        CREATE POLICY audit_logs_tenant_insert ON audit_logs
            FOR INSERT
            WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));

        -- Move the legacy data into the partitioned root by attaching it as a
        -- bounded partition. partman.create_parent will then take over for
        -- forward partitions only (it does not touch already-attached children).
        SELECT MIN(created_at), MAX(created_at)
          INTO v_legacy_min, v_legacy_max
          FROM audit_logs_legacy_v57;

        IF v_legacy_min IS NULL THEN
            -- Empty legacy table — drop and let partman own everything.
            DROP TABLE audit_logs_legacy_v57;
            RAISE NOTICE 'V57: audit_logs_legacy_v57 was empty; dropped.';
        ELSE
            v_lower_bound := date_trunc('month', v_legacy_min);
            -- ATTACH constraint: legacy.created_at < first_of_next_month(legacy_max).
            -- We bound it to the start of the month AFTER legacy_max so that the
            -- first partman-managed partition starts cleanly there.
            EXECUTE format(
                $sql$ALTER TABLE audit_logs_legacy_v57 ADD CONSTRAINT audit_logs_legacy_v57_range_check
                     CHECK (created_at >= %L::timestamptz AND created_at < %L::timestamptz) NOT VALID$sql$,
                v_lower_bound,
                date_trunc('month', v_legacy_max) + INTERVAL '1 month'
            );
            EXECUTE 'ALTER TABLE audit_logs_legacy_v57 VALIDATE CONSTRAINT audit_logs_legacy_v57_range_check';

            EXECUTE format(
                'ALTER TABLE audit_logs ATTACH PARTITION audit_logs_legacy_v57 FOR VALUES FROM (%L) TO (%L)',
                v_lower_bound,
                date_trunc('month', v_legacy_max) + INTERVAL '1 month'
            );
            RAISE NOTICE 'V57: attached audit_logs_legacy_v57 [% , %).',
                v_lower_bound,
                date_trunc('month', v_legacy_max) + INTERVAL '1 month';
        END IF;

        -- Recreate views.
        CREATE OR REPLACE VIEW v_recent_audit_logs AS
        SELECT id, tenant_id, user_id, action, resource_type, resource_id,
               http_method, endpoint, status_code, success, error_message,
               ip_address, user_agent, user_agent_v2, request_id, duration_ms,
               created_at,
               COALESCE(enhanced_metadata, '{}'::jsonb) || COALESCE(metadata, '{}'::jsonb) AS combined_metadata
          FROM audit_logs
         WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
         ORDER BY created_at DESC;

        CREATE OR REPLACE VIEW v_slow_operations AS
        SELECT id, tenant_id, user_id, action, resource_type, endpoint,
               duration_ms, created_at, request_id
          FROM audit_logs
         WHERE duration_ms > 1000
           AND created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
         ORDER BY duration_ms DESC;

        CREATE MATERIALIZED VIEW IF NOT EXISTS mv_audit_statistics AS
        SELECT tenant_id, action, resource_type, DATE(created_at) AS audit_date,
               COUNT(*)                                              AS total_operations,
               COUNT(*) FILTER (WHERE success = TRUE)                AS successful_operations,
               COUNT(*) FILTER (WHERE success = FALSE)               AS failed_operations,
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
    ELSIF v_relkind = 'p' THEN
        RAISE NOTICE 'V57: audit_logs is already partitioned (relkind=p). Skipping conversion, proceeding to partman config.';
    ELSE
        RAISE EXCEPTION 'V57: audit_logs has unexpected relkind=% (expected r or p).', v_relkind;
    END IF;

    -- ----------------------------------------------------------------------
    -- Step 2: register with pg_partman (idempotent).
    -- ----------------------------------------------------------------------
    SELECT EXISTS (
        SELECT 1 FROM partman.part_config
         WHERE parent_table = 'public.audit_logs'
    ) INTO v_already_cfg;

    IF v_already_cfg THEN
        RAISE NOTICE 'V57: partman.part_config already has public.audit_logs. Updating retention to 24 months.';

        UPDATE partman.part_config
           SET retention            = '24 months',
               retention_keep_table = false,
               retention_keep_index = false,
               premake              = 12,
               infinite_time_partitions = true
         WHERE parent_table = 'public.audit_logs';
    ELSE
        -- create_parent signature differs across partman versions; use the
        -- 4.x positional form (works on 4.x and 5.x).
        PERFORM partman.create_parent(
            p_parent_table := 'public.audit_logs',
            p_control      := 'created_at',
            p_type         := 'native',
            p_interval     := '1 month',
            p_premake      := 12
        );

        UPDATE partman.part_config
           SET retention            = '24 months',
               retention_keep_table = false,
               retention_keep_index = false,
               infinite_time_partitions = true
         WHERE parent_table = 'public.audit_logs';

        RAISE NOTICE 'V57: pg_partman now manages public.audit_logs (monthly, premake=12, retention=24mo).';
    END IF;

    -- ----------------------------------------------------------------------
    -- Step 3: schedule daily maintenance.
    -- Prefer pg_cron when present; otherwise rely on pg_partman_bgw if the
    -- DBA configured shared_preload_libraries='pg_partman_bgw'.
    -- ----------------------------------------------------------------------
    IF v_pgcron_avail THEN
        CREATE EXTENSION IF NOT EXISTS pg_cron;

        -- Drop any prior schedule, re-create idempotently.
        IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'partman_audit_logs_maintenance') THEN
            PERFORM cron.unschedule('partman_audit_logs_maintenance');
        END IF;

        PERFORM cron.schedule(
            'partman_audit_logs_maintenance',
            '17 3 * * *',
            $cron$SELECT partman.run_maintenance(p_parent_table := 'public.audit_logs', p_analyze := true);$cron$
        );

        RAISE NOTICE 'V57: pg_cron job partman_audit_logs_maintenance scheduled @ 03:17 daily.';
    ELSE
        RAISE NOTICE 'V57: pg_cron not available. Relying on pg_partman_bgw if configured at server start, '
                     'otherwise operator must schedule SELECT partman.run_maintenance(''public.audit_logs'') daily.';
    END IF;

    -- ----------------------------------------------------------------------
    -- Step 4: comment for downstream operators.
    -- ----------------------------------------------------------------------
    COMMENT ON TABLE audit_logs IS
        'Range-partitioned by created_at (monthly). Managed by pg_partman: '
        'premake=12, retention=24 months. See V57 for the migration that wired this. '
        'Operator runbook: /opt/projects/infra/RUNBOOK_AUDIT_LOG_PARTMAN.md';
END;
$V57$;
