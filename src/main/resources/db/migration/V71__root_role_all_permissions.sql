-- V71: grant the ROOT role EVERY permission.
--
-- The ROOT role (renamed from SUPER_ADMIN in V69) historically held only a partial
-- permission set (32 of 48) — fewer than TENANT_ADMIN (41) — which is confusing in the
-- Roles UI (the top tier appears to have less access). ROOT's ACTUAL power comes from
-- user_type=ROOT, which bypasses permission checks entirely (RbacAuthorizationService),
-- so this is a presentation/consistency fix rather than a privilege change — but the ROOT
-- role should be a true superset. Idempotent: only inserts the permissions it lacks.

INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT '10000000-0000-0000-0000-000000000001', p.id, now()
FROM permissions p
WHERE NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = '10000000-0000-0000-0000-000000000001'
      AND rp.permission_id = p.id
);
