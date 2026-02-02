package com.fivucsas.identity.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * Custom Spring Security PermissionEvaluator that integrates with the RBAC system.
 *
 * <p>Enables {@code @PreAuthorize("hasPermission(#id, 'user', 'read')")} expressions
 * that respect the user type hierarchy (ROOT bypasses, TENANT_ADMIN has implicit access).
 *
 * <p>Usage in controllers:
 * <pre>
 * {@code @PreAuthorize("hasPermission(null, 'user', 'read')")}
 * public ResponseEntity<List<UserDto>> listUsers() { ... }
 *
 * {@code @PreAuthorize("@rbac.hasPermission('user:read')")}
 * public ResponseEntity<UserDto> getUser() { ... }
 * </pre>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RbacPermissionEvaluator implements PermissionEvaluator {

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
     * @param targetId the target object ID
     * @param targetType the target object type (resource name, e.g., "user")
     * @param permission the permission action (e.g., "read")
     * @return true if the user has the permission
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
                                  String targetType, Object permission) {
        if (authentication == null || targetType == null || permission == null) return false;

        String permissionStr = targetType.toLowerCase() + ":" + permission.toString().toLowerCase();
        log.debug("Evaluating permission '{}' for user '{}'", permissionStr, authentication.getName());

        return rbacService.hasPermission(permissionStr);
    }
}
