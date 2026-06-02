-- V81: enforce the "all-methods" biometric-consent SINGLETON (P1-7, 2026-06-02).
--
-- Problem:
--   V68 created `uq_identity_tenant_biometric_consent UNIQUE (identity_id,
--   tenant_id, method)` and its comment ASSERTED that this guarantees "at most
--   ONE row may exist with method = NULL per (identity, tenant)". That is BACKWARDS:
--   Postgres treats NULLs as DISTINCT in a UNIQUE constraint (the pre-15 default,
--   and the default here since the constraint has no NULLS NOT DISTINCT clause),
--   so the constraint does NOT block duplicate method=NULL ("all-methods") rows.
--   Consequences:
--     * two+ "all-methods" consent rows can coexist for the same (identity, tenant);
--     * BiometricConsentService.setConsent upserts via
--       findByIdentityIdAndTenantIdAndMethod(.., null) which returns Optional —
--       with duplicates that derived query throws NonUniqueResultException (HTTP 500);
--     * listConsents / resolution see contradictory all-methods rows.
--
-- Fix (additive + idempotent):
--   (1) DEDUPE existing method=NULL rows: keep the most-recently-decided row per
--       (identity_id, tenant_id) — newest updated_at, then created_at, then id as a
--       stable tie-break — and DELETE the rest. No-op when already unique.
--   (2) Add a PARTIAL UNIQUE INDEX on (identity_id, tenant_id) WHERE method IS NULL
--       so the database now actually enforces the all-methods singleton going
--       forward. The method-specific rows stay covered by the V68 constraint
--       (NULLs-distinct does not affect non-NULL methods), so the two coexist.
--
-- Self-gating / safe: step (1) makes the WHERE-method-IS-NULL subset unique BEFORE
--   step (2) builds the index, so CREATE UNIQUE INDEX cannot fail on existing data.
--   CREATE INDEX IF NOT EXISTS makes a re-run a no-op. Applies cleanly from Flyway
--   head V80. The method-specific UNIQUE from V68 is intentionally left in place.

-- (1) Dedupe duplicate all-methods (method IS NULL) rows, keeping the latest decision.
DELETE FROM identity_tenant_biometric_consent c
USING (
    SELECT id,
           row_number() OVER (
               PARTITION BY identity_id, tenant_id
               ORDER BY updated_at DESC NULLS LAST,
                        created_at DESC NULLS LAST,
                        id DESC
           ) AS rn
    FROM identity_tenant_biometric_consent
    WHERE method IS NULL
) dup
WHERE c.id = dup.id
  AND dup.rn > 1;

-- (2) Enforce the all-methods singleton at the database level.
CREATE UNIQUE INDEX IF NOT EXISTS uq_itbc_all_methods_singleton
    ON identity_tenant_biometric_consent (identity_id, tenant_id)
    WHERE method IS NULL;

COMMENT ON INDEX uq_itbc_all_methods_singleton IS
    'P1-7: enforces at most ONE all-methods (method IS NULL) consent row per '
    '(identity, tenant). The V68 (identity, tenant, method) UNIQUE does NOT cover '
    'this because Postgres treats NULL methods as distinct.';
