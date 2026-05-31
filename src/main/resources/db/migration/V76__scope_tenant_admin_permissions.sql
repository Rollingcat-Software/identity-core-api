-- V76: scope tenant-scoped TENANT_ADMIN roles to TENANT-level permissions only.
--
-- The fivucsas TENANT_ADMIN role held all 48 permissions — identical to the
-- global ROOT role — which is both over-privileged and misleading in the Roles
-- UI (a tenant admin appeared to have the same platform power as the platform
-- owner). A TENANT_ADMIN manages its OWN tenant; PLATFORM-level grants belong to
-- ROOT (user_type=ROOT bypasses permission checks anyway). This removes the
-- seven platform-scoped grants from EVERY tenant-scoped TENANT_ADMIN role:
--   tenant.create / tenant.delete           — provisioning/destroying tenants
--   system.audit / system.configure         — platform-wide operations
--   permission.create/update/delete         — permissions are a global catalog
-- Kept: tenant.read/update/configure/members (own-tenant admin), role.* (manage
-- roles within the tenant), permission.read, user.*, auth_flow.*, etc.
--
-- ROOT (tenant_id IS NULL) is untouched and retains all 48 (see V71).
-- Idempotent: a re-run deletes nothing once the grants are gone.

DELETE FROM role_permissions rp
USING roles r, permissions p
WHERE rp.role_id = r.id
  AND rp.permission_id = p.id
  AND r.name = 'TENANT_ADMIN'
  AND r.tenant_id IS NOT NULL
  AND p.name IN (
      'tenant.create', 'tenant.delete',
      'system.audit', 'system.configure',
      'permission.create', 'permission.update', 'permission.delete'
  );
