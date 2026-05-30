package com.fivucsas.identity.security;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

/**
 * Service for authorization checks used in @PreAuthorize expressions.
 * Provides methods to check ownership, tenant membership, and permissions.
 */
@Service("authz")
@RequiredArgsConstructor
public class AuthorizationService {

    private final UserRepository userRepository;

    /**
     * Checks if the current user owns the specified resource.
     *
     * @param resourceId the resource ID to check
     * @return true if current user's ID matches the resource ID
     */
    public boolean isOwner(UUID resourceId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CustomUserDetails details) {
            return details.getUserId().equals(resourceId);
        }
        return false;
    }

    /**
     * Checks if the current user belongs to the specified tenant.
     *
     * @param tenantId the tenant ID to check
     * @return true if current user's tenant ID matches
     */
    public boolean isSameTenant(UUID tenantId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CustomUserDetails details) {
            return details.getTenantId() != null && details.getTenantId().equals(tenantId);
        }
        return false;
    }

    /**
     * Checks if the current user can manage the specified user.
     * Rules:
     * - ROOT can manage anyone
     * - TENANT_ADMIN can manage users in their tenant
     * - Regular users can only manage themselves
     *
     * @param targetUserId the user ID to manage
     * @return true if current user has permission to manage the target user
     */
    public boolean canManageUser(UUID targetUserId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof CustomUserDetails details)) {
            return false;
        }

        // Root (platform owner) can manage anyone
        if (hasRole("ROOT")) {
            return true;
        }

        // Tenant admin can manage users in their tenant
        if (hasRole("TENANT_ADMIN")) {
            Optional<User> targetUser = userRepository.findById(targetUserId);
            if (targetUser.isPresent() && targetUser.get().getTenant() != null) {
                UUID targetTenantId = targetUser.get().getTenant().getId();
                return details.getTenantId() != null && details.getTenantId().equals(targetTenantId);
            }
            return false;
        }

        // Users can only manage themselves
        return details.getUserId().equals(targetUserId);
    }

    /**
     * Checks if the current user has the specified role.
     *
     * @param role the role name (without ROLE_ prefix)
     * @return true if user has the role
     */
    public boolean hasRole(String role) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            return false;
        }
        return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + role));
    }

    /**
     * Checks if the current user has the specified permission.
     *
     * @param permission the permission code (e.g., "user:read")
     * @return true if user has the permission
     */
    public boolean hasPermission(String permission) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            return false;
        }
        return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(permission));
    }

    /**
     * Gets the current user ID from the security context.
     *
     * @return the current user ID, or null if not authenticated
     */
    public UUID getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CustomUserDetails details) {
            return details.getUserId();
        }
        return null;
    }

    /**
     * Gets the current tenant ID from the security context.
     *
     * @return the current tenant ID, or null if not authenticated
     */
    public UUID getCurrentTenantId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CustomUserDetails details) {
            return details.getTenantId();
        }
        return null;
    }
}
