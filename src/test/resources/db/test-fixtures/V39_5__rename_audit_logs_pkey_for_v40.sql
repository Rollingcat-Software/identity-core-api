-- ============================================================================
-- TEST-ONLY MIGRATION (loaded only by Testcontainers integration profile via
-- spring.flyway.locations=classpath:db/migration,classpath:db/test-fixtures).
-- This file is NOT on the production classpath; it never runs in prod.
-- ============================================================================
--
-- WHY THIS EXISTS
-- ---------------
-- V40__partition_audit_logs.sql RENAMEs the V5-created audit_logs heap to
-- audit_logs_legacy, then CREATEs a new partitioned audit_logs root, then
-- adds a composite primary key constraint named `audit_logs_pkey`:
--
--     ALTER TABLE audit_logs
--         ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id, created_at);
--
-- That last statement fails on a fresh Testcontainers PG database with:
--
--     ERROR: relation "audit_logs_pkey" already exists
--
-- because PostgreSQL keeps the PK index name attached to the renamed table.
-- V5 declared `id UUID PRIMARY KEY` inline, which auto-named the constraint
-- and its backing index `audit_logs_pkey`. RENAME TABLE does NOT rename
-- contained constraints/indexes (verified locally on pg_17). So after V40's
-- `ALTER TABLE audit_logs RENAME TO audit_logs_legacy`, the legacy table
-- still owns the global name `audit_logs_pkey`, and the subsequent
-- `ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id, created_at)` collides.
--
-- This causes every Testcontainers integration-tests CI run to fail at V40
-- with the above error (visible in PR #99/#100 CI logs 2026-05-12). The
-- failure is `continue-on-error: true` in .github/workflows/ci.yml so PRs
-- still merge, but every PR's checks page shows a red Integration tests box.
--
-- WHY WE ARE NOT EDITING V40 IN PLACE
-- ----------------------------------
-- V40 is in production's flyway_schema_history with a fixed checksum and
-- our prod profile keeps Flyway's default validate-on-migrate=true. Editing
-- V40's body would force a checksum mismatch and require manual `flyway
-- repair` on prod. Three previous in-place V40 fixes (commits 2b00a7b,
-- a30287b, 81101f0) were each reverted (43d0050, 614a94f, f404d12) for
-- this reason. A test-only fixture has zero prod surface area and exactly
-- matches the V28_5 precedent for the V29 FK-violation bug.
--
-- WHY PROD DOESN'T HIT THIS
-- ------------------------
-- V40 was BASELINE-SKIPPED on prod in 2026-04 (see V57 header comment:
-- "DB review 2026-04-30 §4 found V40/V41 also rolled back in prod via
-- BASELINE SKIP markers"). Prod's flyway_schema_history records V40 as
-- success=t but the migration never actually ran, so the PG name collision
-- never surfaced there. Prod's audit_logs is still relkind='r' (plain
-- heap), with the original V5-named `audit_logs_pkey` constraint intact.
-- V57 (idempotent partman-aware partitioning) is the prod-side path: it
-- detects relkind='r' and converts on the fly when partman is available,
-- which the operator wires via Option A (custom pgvector+partman image,
-- documented in OPERATOR_ACTIONS_2026-05-12.md item 1).
--
-- WHAT THIS FIXTURE DOES
-- ----------------------
-- Renames the V5 audit_logs PK constraint from `audit_logs_pkey` to
-- `audit_logs_v5_pkey`, freeing the name `audit_logs_pkey` for V40's
-- composite PK ADD. Idempotent: only renames if `audit_logs_pkey` is
-- attached to a plain heap named `audit_logs` (the pre-V40 state).
--
-- VERIFICATION
-- ------------
-- Reproduced locally against pgvector/pgvector:pg17:
--   1) CREATE TABLE audit_logs (id UUID PRIMARY KEY, created_at timestamp);
--   2) ALTER TABLE audit_logs RENAME TO audit_logs_legacy;
--   3) CREATE TABLE audit_logs (...) PARTITION BY RANGE (created_at);
--   4) ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id, created_at);
--      => ERROR: relation "audit_logs_pkey" already exists
--
-- With this fixture inserted between step 1 and step 2, step 4 succeeds.
-- ============================================================================

DO $$
BEGIN
    -- Only act when audit_logs is still a plain heap (V40 has not yet run)
    -- AND the V5-default constraint name is present. This is the only state
    -- where the rename is meaningful; everywhere else (already partitioned,
    -- already renamed) the migration falls through silently.
    IF EXISTS (
        SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE c.relname = 'audit_logs'
           AND n.nspname = 'public'
           AND c.relkind = 'r'
    ) AND EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'audit_logs_pkey'
           AND conrelid = 'public.audit_logs'::regclass
    ) THEN
        EXECUTE 'ALTER TABLE public.audit_logs '
             || 'RENAME CONSTRAINT audit_logs_pkey TO audit_logs_v5_pkey';
        RAISE NOTICE 'V39_5: renamed audit_logs_pkey -> audit_logs_v5_pkey to free the name for V40.';
    ELSE
        RAISE NOTICE 'V39_5: audit_logs not in pre-V40 state; rename skipped (no-op).';
    END IF;
END $$;
