-- V82: oauth2_clients.cross_tenant — EXPLICIT cross-tenant authorization flag.
--
-- Replaces the IMPLICIT rule in OAuth2Controller.validateAuthorizeRequest that
-- granted "authenticate users from ALL tenants" to any client whose tenant_id
-- equaled the `system` sentinel tenant (00000000-0000-0000-0000-000000000000).
-- That coupling was invisible in the data: nothing in the row said "this client
-- is platform/first-party", you had to know the sentinel UUID. This column makes
-- the capability EXPLICIT and AUDITABLE — a reviewer can read it straight off the
-- table, and a customer-tenant client can never accidentally inherit it by being
-- (mis)bound to the system tenant.
--
-- A cross_tenant=TRUE client may mint authorization codes for users from EVERY
-- tenant (first-party platform apps: the web dashboard, the native mobile app).
-- A cross_tenant=FALSE client (default) stays strictly isolated to its own tenant.
-- The minted token still carries the USER's real tenant_id, so downstream
-- multi-tenant isolation is unaffected either way.
--
-- Additive, idempotent, default-safe: existing rows default to FALSE (no
-- behavior change for customer-tenant clients); the two known first-party
-- platform clients are flipped to TRUE to preserve today's cross-tenant login.

ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS cross_tenant BOOLEAN NOT NULL DEFAULT FALSE;

-- Preserve current behavior: the first-party platform clients that previously
-- relied on the system-tenant implicit rule keep cross-tenant authorization.
-- Idempotent — re-running flips nothing already TRUE and matches by stable
-- client_id, so it is safe on a fresh DB or a re-applied chain.
UPDATE oauth2_clients
   SET cross_tenant = TRUE
 WHERE client_id IN ('fivucsas-mobile', 'fivucsas-web-dashboard');
