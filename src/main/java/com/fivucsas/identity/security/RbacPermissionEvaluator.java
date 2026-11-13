package com.fivucsas.identity.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Locale;

/**
 * Custom Spring Security PermissionEvaluator that integrates with the RBAC system.
 *
 * <p>Enables {@code @PreAuthorize("hasPermission(#id, 'user', 'read')")} expressions
 * that respect the user type hierarchy (ROOT bypasses, TENANT_ADMIN has implicit access).
 * A check with a non-null target id also requires the target user or tenant to belong
 * to the caller's tenant (see {@link #hasPermission(Authentication, Serializable, String, Object)}).
 *
 * <p>Usage in controllers:
 * <pre>
 * {@code @PreAuthorize("hasPermission(null, 'user', 'read')")}
 * public ResponseEntity<List<UserResponse>> listUsers() { ... }
 *
 * {@code @PreAuthorize("@rbac.hasPermission('user:read')")}
 * public ResponseEntity<UserResponse> getUser() { ... }
 * </pre>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RbacPermissionEvaluator implements PermissionEvaluator {

    /** Target types whose id names a user; the user must belong to the caller's tenant. */
    static final String TARGET_USER = "user";
    static final String TARGET_USER_SETTINGS = "user_settings";
    /** Target type whose id names a tenant; it must be the caller's tenant. */
    static final String TARGET_TENANT = "tenant";

    private final RbacAuthorizationService rbacService;

    /**
     * Evaluates permission for a target object.
     *
     * @param authentication the current authentication
     * @param targetDomainObject the target domain object (can be null for collection operations)
     * @param permission the permission string (e.g., "user:read")
     * @return true if the user has the permission
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || permission == null) return false;

        String permissionStr = permission.toString();
        log.debug("Evaluating permission '{}' for user '{}'", permissionStr, authentication.getName());

        return rbacService.hasPermission(permissionStr);
    }

    /**
     * Evaluates permission for a target identified by type and ID.
     *
     * @param authentication the current authentication
     * @param targetId the target object ID; when non-null it must be inside the caller's tenant
     * @param targetType the target object type (resource name, e.g., "user")
     * @param permission the permission action (e.g., "read")
     * @return true if the user has the permission and may reach the target
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
                                  String targetType, Object permission) {
        if (authentication == null || targetType == null || permission == null) return false;

        // Locale.ROOT: permission names are ASCII identifiers; under the Turkish
        // locale a bare toLowerCase() maps I→ı / İ→i, so "DEVICE:READ" could be
        // cased to a string that no longer matches the seeded "device:read"
        // authority — silently denying (or, depending on data, granting) access.
        String type = targetType.toLowerCase(Locale.ROOT);
        String permissionStr = type + ":" + permission.toString().toLowerCase(Locale.ROOT);
        log.debug("Evaluating permission '{}' for user '{}'", permissionStr, authentication.getName());

        if (!rbacService.hasPermission(permissionStr)) {
            return false;
        }
        return targetId == null || isTargetInCallerTenant(type, targetId);
    }

    /**
     * The permission alone does not authorize a targeted check: a TENANT_ADMIN holds
     * every tenant-scoped permission implicitly, so without this an admin of one tenant
     * passes {@code hasPermission(#userId, 'User', ...)} for a user of any tenant. The
     * target must sit in the caller's tenant (ROOT stays cross-tenant). A target type
     * without a rule here is refused, so a new targeted expression fails closed until
     * its type is mapped.
     */
    private boolean isTargetInCallerTenant(String type, Serializable targetId) {
        String id = targetId.toString();
        return switch (type) {
            case TARGET_USER, TARGET_USER_SETTINGS -> rbacService.canAccessUser(id);
            case TARGET_TENANT -> rbacService.canAccessTenant(id);
            default -> {
                log.warn("AUDIT: targeted permission check refused, no tenant rule for target type '{}'", type);
                yield false;
            }
        };
    }
}
