-- V89: Public device benchmark runs (Paper A, Facenet512 FP16 in the browser).
--
-- Anyone may run app.fivucsas.com/devbench without an account; each finished run
-- is POSTed to the public, rate-limited, write-only POST /api/v1/devbench/runs and
-- stored here. Only ROOT can read the rows back (GET /api/v1/admin/devbench/runs).
--
-- Design notes:
--   * Not tenant-scoped (no RLS, no Hibernate tenantFilter): anonymous research
--     data with no tenant context, never joined to users.
--   * No IP address, no account id, no precise location is stored. The only
--     free text a person types is the optional participant name, kept inside the
--     payload and capped at 60 characters by the API.
--   * payload holds the sanitised run document (allow-listed top-level keys,
--     body capped at 32 KiB by the API), so the JSON fields stay identical to the
--     earlier artifact export and the data sets remain comparable.
-- Additive; reversible by DROP TABLE.

CREATE TABLE IF NOT EXISTS devbench_runs (
    id          UUID         PRIMARY KEY,
    received_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tool        VARCHAR(80)  NOT NULL,
    batch_id    VARCHAR(64)  NOT NULL,
    run_index   SMALLINT     NOT NULL,
    device_key  VARCHAR(120),
    payload     JSONB        NOT NULL
);

-- Daily intake cap and chronological export both scan by arrival time.
CREATE INDEX IF NOT EXISTS idx_devbench_runs_received_at ON devbench_runs (received_at);
