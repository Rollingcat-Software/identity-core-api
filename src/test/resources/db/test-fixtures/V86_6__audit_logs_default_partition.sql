-- ============================================================================
-- TEST-ONLY MIGRATION (Testcontainers integration profile only; never in prod).
-- ============================================================================
--
-- Companion to V39_6. After the chain, audit_logs (partitioned by V40) has
-- partitions only up to 2026-06 because V57's pg_partman maintenance is a
-- no-op without the extension (the Testcontainers image does not ship it).
-- Any audit write dated later (i.e. every write the tests make after
-- 2026-06-30) would fail with "no partition ... found for row".
-- A DEFAULT partition catches them. Guarded so it is a no-op if audit_logs
-- is not partitioned or already has a default partition.
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class
                WHERE relname = 'audit_logs' AND relkind = 'p'
                  AND relnamespace = current_schema()::regnamespace)
       AND NOT EXISTS (SELECT 1 FROM pg_partitioned_table pt
                        JOIN pg_class c ON c.oid = pt.partrelid
                       WHERE c.relname = 'audit_logs'
                         AND c.relnamespace = current_schema()::regnamespace
                         AND pt.partdefid <> 0) THEN
        CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;
    END IF;
END
$$;
