package com.fivucsas.identity.domain.model.user;

/**
 * Domain enum for hierarchical user types.
 * Pure domain concept - no infrastructure dependencies.
 *
 * Hierarchy (highest to lowest privilege):
 * ROOT > TENANT_ADMIN > TENANT_MEMBER > GUEST
 */
public enum UserType {

    ROOT(100),
    TENANT_ADMIN(80),
    TENANT_MEMBER(50),
    GUEST(10);

    private final int hierarchyLevel;

    UserType(int hierarchyLevel) {
        this.hierarchyLevel = hierarchyLevel;
    }

    public int getHierarchyLevel() {
        return hierarchyLevel;
    }

    public boolean outranks(UserType other) {
        return this.hierarchyLevel > other.hierarchyLevel;
    }

    public boolean isAtLeast(UserType other) {
        return this.hierarchyLevel >= other.hierarchyLevel;
    }

    public boolean canManage(UserType targetType) {
        if (this == ROOT) return true;
        return this.outranks(targetType);
    }

    public boolean requiresExpiration() {
        return this == GUEST;
    }

    public boolean hasImplicitTenantAccess() {
        return this == ROOT || this == TENANT_ADMIN;
    }
}
