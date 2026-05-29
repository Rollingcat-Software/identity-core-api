-- V68: Identity & Account-Linking — Phase 3 (Model A: biometric on the identity
-- + per-tenant consent).
--
-- Introduces the cross-tenant/identity CONSENT ledger. A person (identity) holds
-- ONE biometric template (Model A); a tenant may VERIFY against it only when that
-- person has GRANTED consent for that tenant. The api orchestration layer reads
-- this table to decide whether a verify in tenant T may be routed to the person's
-- CANONICAL enrollment (the membership where they actually enrolled) under another
-- membership of the SAME identity. The raw template/embedding is never shared — the
-- tenant only ever receives a verify DECISION.
--
-- LOW-RISK by design: this does NOT re-key the biometric-processor's pgvector
-- store (that would be a high-risk migration on the most sensitive data — AVOIDED
-- per the Phase 3 design constraint). "One template per person" is achieved at the
-- api layer by designating a canonical (identity, method) enrollment and routing
-- consented verifies to it.
--
-- CROSS-TENANT TABLE — NO @Filter(tenantFilter) on the entity. Like `identities`
-- and `identity_emails`, this table is platform-level by definition: it links a
-- platform identity to a tenant. Tenant isolation is preserved at the MEMBERSHIP
-- (`users`) layer and by the consent GRANT itself (a tenant can only act on a
-- person who explicitly opted in). Filtering this table by tenant would break the
-- identity-authority model. See docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md
-- ("Cross-cutting rules") and the Identity entity Javadoc.
--
-- Applies cleanly from the current prod schema (Flyway head V67). Idempotent:
-- CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS identity_tenant_biometric_consent (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities (id),
    tenant_id   UUID NOT NULL REFERENCES tenants (id),
    -- NULL method = consent applies to ALL biometric methods (FACE, VOICE, ...).
    -- A specific value (e.g. 'FACE') scopes consent to that one method.
    method      TEXT,
    granted     BOOLEAN NOT NULL DEFAULT true,
    granted_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- One consent row per (identity, tenant, method). A NULL method and a named
    -- method coexist as distinct rows. Postgres treats NULLs as DISTINCT in a
    -- UNIQUE constraint, so at most ONE row may exist with method = NULL per
    -- (identity, tenant) — which is the intended "all-methods" singleton.
    CONSTRAINT uq_identity_tenant_biometric_consent
        UNIQUE (identity_id, tenant_id, method)
);

CREATE INDEX IF NOT EXISTS idx_itbc_identity
    ON identity_tenant_biometric_consent (identity_id);
CREATE INDEX IF NOT EXISTS idx_itbc_identity_tenant
    ON identity_tenant_biometric_consent (identity_id, tenant_id);

COMMENT ON TABLE identity_tenant_biometric_consent IS
    'Per-(identity, tenant[, method]) consent for a tenant to VERIFY against the '
    'person''s canonical biometric template (Model A, Phase 3). Cross-tenant / '
    'platform-level — deliberately NOT tenant-filtered. See '
    'docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md.';
COMMENT ON COLUMN identity_tenant_biometric_consent.method IS
    'NULL = all biometric methods; a value (e.g. FACE) scopes consent to that method.';
COMMENT ON COLUMN identity_tenant_biometric_consent.granted IS
    'true = tenant may verify against the person''s canonical template; false = '
    'explicitly revoked. Absence of a row = no consent (default-deny).';
