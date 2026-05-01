-- Convert shedlock.lock_until / locked_at from TIMESTAMP (no TZ) to
-- TIMESTAMP WITH TIME ZONE so cross-row queries / audit joins against
-- the rest of the schema (which uses TIMESTAMP WITH TIME ZONE
-- everywhere) don't hit timezone-conversion surprises.
--
-- ShedLock with `usingDbTime()` writes UTC; the USING clause below
-- preserves the existing values by re-interpreting them as UTC instants.
--
-- Follow-up to V51 (Copilot post-merge finding on PR #43, round 3).

ALTER TABLE shedlock
    ALTER COLUMN lock_until TYPE TIMESTAMP WITH TIME ZONE
        USING lock_until AT TIME ZONE 'UTC';

ALTER TABLE shedlock
    ALTER COLUMN locked_at  TYPE TIMESTAMP WITH TIME ZONE
        USING locked_at  AT TIME ZONE 'UTC';
