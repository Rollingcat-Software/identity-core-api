package com.fivucsas.identity.entity;

/**
 * Hierarchical user type defining the user's fundamental identity in the system.
 *
 * <p>Hierarchy (highest to lowest privilege):
 * <ol>
 *   <li>{@link #ROOT} - Platform super administrator, cross-tenant access</li>
 *   <li>{@link #TENANT_ADMIN} - Full control within their tenant</li>
 *   <li>{@link #TENANT_MEMBER} - Permissions assigned by tenant admin (default: viewer)</li>
 *   <li>{@link #GUEST} - Time-limited access, no default permissions, auto-purged on expiry</li>
 * </ol>
 *
 * <p>UserType is identity (who you are), Roles are capability (what you can do).
 * ROOT bypasses all permission checks. TENANT_ADMIN has implicit full access within their tenant.
 */
public enum UserType {

    /**
     * Platform-level super administrator.
     * Has unrestricted access across all tenants.
     * Cannot be created through normal registration - must be seeded or promoted by another ROOT.
     */
    ROOT(100),

    /**
     * Tenant administrator with full control over their organization.
     * Can manage members, guests, roles, and all resources within their tenant.
     * Cannot access other tenants or system-level configuration.
     */
    TENANT_ADMIN(80),

    /**
     * Regular tenant member.
     * Permissions are determined by assigned roles (default: TENANT_VIEWER).
     * Tenant admin can promote to editor or assign custom roles.
     */
    TENANT_MEMBER(50),

    /**
     * Time-limited guest user.
     * Has no permissions by default unless explicitly granted by tenant admin.
     * Account is automatically soft-deleted and fully cleaned up when expires_at is reached.
     */
    GUEST(10);

    private final int hierarchyLevel;

    UserType(int hierarchyLevel) {
        this.hierarchyLevel = hierarchyLevel;
    }

    /**
     * Returns the hierarchy level for comparison.
     * Higher value = higher privilege.
     */
    public int getHierarchyLevel() {
        return hierarchyLevel;
    }

    /**
     * Checks if this user type outranks the given type.
     */
    public boolean outranks(UserType other) {
        return this.hierarchyLevel > other.hierarchyLevel;
    }

    /**
     * Checks if this user type is at least as privileged as the given type.
     */
    public boolean isAtLeast(UserType other) {
        return this.hierarchyLevel >= other.hierarchyLevel;
    }

    /**
     * Checks if this type can manage users of the given type.
     * ROOT can manage everyone. TENANT_ADMIN can manage TENANT_MEMBER and GUEST.
     * Nobody can manage users of equal or higher rank (except ROOT managing ROOT).
     */
    public boolean canManage(UserType targetType) {
        if (this == ROOT) return true;
        return this.outranks(targetType);
    }

    /**
     * Checks if this user type requires an expiration time.
     */
    public boolean requiresExpiration() {
        return this == GUEST;
    }

    /**
     * Checks if this user type has implicit tenant-wide access.
     */
    public boolean hasImplicitTenantAccess() {
        return this == ROOT || this == TENANT_ADMIN;
    }
}
