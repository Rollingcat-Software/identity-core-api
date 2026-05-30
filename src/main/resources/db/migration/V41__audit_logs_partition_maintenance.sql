-- V41: audit_logs partition maintenance helper
-- ---------------------------------------------------------------------------
-- Companion to V40. Adds ensure_audit_logs_partition(target_month date)
-- which creates a monthly partition if it does not already exist.
--
-- Operational use: run via cron once per month (e.g., on the 25th) to
-- pre-create the partition for the month after next, preserving the 2-month
-- look-ahead guarantee from V40.
--
-- Example cron (on the Postgres host or a scheduler container):
--   0 3 25 * *   psql "$PG_URL" -c \
--     "SELECT ensure_audit_logs_partition(date_trunc('month', now() + interval '2 months')::date);"
--
-- The function is idempotent: if the partition already exists it returns
-- false and does nothing. It raises NOTICE on creation for cron log trails.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ensure_audit_logs_partition(target_month date)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
    partition_name text;
    range_start    date;
    range_end      date;
BEGIN
    -- Normalize to the first day of the month.
    range_start := date_trunc('month', target_month)::date;
    range_end   := (range_start + INTERVAL '1 month')::date;
    partition_name := format('audit_logs_%s', to_char(range_start, 'YYYY_MM'));

    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = partition_name
          AND n.nspname = current_schema()
    ) THEN
        RAISE NOTICE 'Partition % already exists; no action.', partition_name;
        RETURN false;
    END IF;

    EXECUTE format(
        'CREATE TABLE %I PARTITION OF audit_logs FOR VALUES FROM (%L) TO (%L)',
        partition_name, range_start, range_end
    );

    RAISE NOTICE 'Created audit_logs partition % [% , %).',
        partition_name, range_start, range_end;
    RETURN true;
END;
$$;

-- Single string literal — `'a' || 'b'` is a syntax error in a COMMENT IS clause
-- (would fail a from-zero run; the previous `||` form had never executed).
COMMENT ON FUNCTION ensure_audit_logs_partition(date) IS
    'Creates the monthly audit_logs partition for the given target_month if missing. Schedule monthly via cron (user action): SELECT ensure_audit_logs_partition(date_trunc(''month'', now() + interval ''2 months'')::date); Companion to V40 (IN-H5).';
