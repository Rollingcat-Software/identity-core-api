-- V37: Ensure index on oauth2_clients(tenant_id) for /authorize hot path
--
-- The 2026-04-16 five-agent audit (see web-app/docs/AUDIT_REPORT_2026-04-16.md)
-- flagged a sequential scan on oauth2_clients when the OAuth2 authorize flow
-- resolves the caller's tenant via client_id -> tenant_id. On multi-tenant
-- deployments with hundreds of registered clients this showed up as a
-- measurable latency tail on /api/v1/oauth2/authorize and /authorize/complete.
--
-- V24 already declared this index, but it may be missing on environments that
-- were bootstrapped before V24 landed, or on replicas where the index build
-- silently failed. This migration reaffirms the index idempotently using
-- CREATE INDEX IF NOT EXISTS so it is safe to re-run.
--
-- If the index already exists (V24 applied cleanly), this statement is a
-- no-op — no table lock, no rewrite. If missing, Postgres builds it here.

CREATE INDEX IF NOT EXISTS idx_oauth2_clients_tenant_id
    ON oauth2_clients(tenant_id);
