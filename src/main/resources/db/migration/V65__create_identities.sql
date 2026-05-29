-- V65: Identity & Account-Linking — Phase 1 (foundation, ZERO behavior change)
--
-- Introduces the platform-level PERSON/IDENTITY layer described in
-- docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md (Model A, approved 2026-05-29).
--
-- Today one `users` row fuses three concerns: the PERSON, their authentication
-- identity, and their tenant MEMBERSHIP. This table extracts the PERSON into a
-- cross-tenant `identities` row. `users` rows become tenant memberships that
-- reference an identity (V67 adds the FK + backfill).
--
-- DESIGN NOTE — NOT TENANT-SCOPED: `identities` is deliberately a platform-level
-- table. It carries NO tenant_id and is NOT covered by the Hibernate
-- `tenantFilter` (P0-1). Tenant isolation is preserved at the MEMBERSHIP
-- (`users`) and (later) CONSENT layers, never by hiding the identity. See the
-- "Cross-cutting rules" section of the design doc.
--
-- `gen_random_uuid()` is a PostgreSQL core function (PG13+); no extension is
-- required (the DB is PG17). uuid-ossp is also available from V0 if ever needed.

CREATE TABLE IF NOT EXISTS identities
(
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name TEXT,
    status       TEXT        NOT NULL    DEFAULT 'ACTIVE',
    created_at   TIMESTAMPTZ NOT NULL    DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL    DEFAULT now()
);

COMMENT ON TABLE identities IS
    'Platform-level PERSON layer (Model A, Phase 1). Cross-tenant by design — '
    'NOT tenant-scoped, NO tenantFilter. See docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md.';
