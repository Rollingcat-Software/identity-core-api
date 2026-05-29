package com.fivucsas.identity.security;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Central RBAC authorization service implementing hierarchical access control.
 *
 * <p>Authorization hierarchy:
 * <ul>
 *   <li>ROOT: Bypasses all permission checks, cross-tenant access</li>
 *   <li>TENANT_ADMIN: Full access within own tenant, can manage members and guests</li>
 *   <li>TENANT_MEMBER: Access determined by assigned roles</li>
 *   <li>GUEST: Access determined by assigned roles, time-limited</li>
 * </ul>
 *
 * <p>Used by Spring Security {@code @PreAuthorize} expressions via the custom
 * {@link RbacPermissionEvaluator}.
 */
@Service("rbac")
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class RbacAuthorizationService {

    private final UserRepository userRepository;
    private final TenantFilterBypass tenantFilterBypass;

    /**
     * Checks if the current user has the given permission.
     * ROOT users bypass this check entirely.
     * TENANT_ADMIN users have implicit access to all tenant-scoped permissions.
     */
    public boolean hasPermission(String permission) {
        User currentUser = getCurrentUser().orElse(null);
        if (currentUser == null) return false;
        return hasPermission(currentUser, permission);
    }

    /**
     * Checks if the given user has the specified permission.
     */
    public boolean hasPermission(User user, String permission) {
        if (user == null || permission == null) return false;

        // ROOT bypasses all permission checks
        if (user.getUserType() == UserType.ROOT) {
            log.trace("ROOT user {} bypasses permission check: {}", user.getEmail(), permission);
            return true;
        }

        // Expired guests have no permissions
        if (user.isExpired()) {
            log.debug("Expired guest user {} denied permission: {}", user.getEmail(), permission);
            return false;
        }

        // TENANT_ADMIN has implicit access to all tenant-scoped permissions
        if (user.getUserType() == UserType.TENANT_ADMIN && !isSystemPermission(permission)) {
            log.trace("TENANT_ADMIN {} has implicit access to: {}", user.getEmail(), permission);
            return true;
        }

        // For TENANT_MEMBER and GUEST, check role-based permissions
        return user.hasPermission(permission);
    }

    /**
     * Checks if the current user can manage the target user.
     * Based on user type hierarchy and tenant scope.
     */
    public boolean canManageUser(UUID targetUserId) {
        User currentUser = getCurrentUser().orElse(null);
        if (currentUser == null) return false;

        // ROOT can manage anyone
        if (currentUser.getUserType() == UserType.ROOT) return true;

        User targetUser = userRepository.findById(targetUserId).orElse(null);
        if (targetUser == null) return false;

        return currentUser.canManage(targetUser);
    }

    /**
     * Checks if the current user can access resources within the given tenant.
     */
    public boolean canAccessTenant(UUID tenantId) {
        User currentUser = getCurrentUser().orElse(null);
        if (currentUser == null) return false;

        // ROOT has cross-tenant access
        if (currentUser.getUserType() == UserType.ROOT) return true;

        // Others can only access their own tenant
        return currentUser.getTenant() != null
            && currentUser.getTenant().getId().equals(tenantId);
    }

    /**
     * String-typed overload of {@link #canAccessTenant(UUID)} for SpEL
     * expressions whose source field is a {@code String} (e.g. JSON request
     * DTOs). Fail-closed on null/blank/malformed input — a missing tenantId
     * never grants access, and a non-UUID string returns false instead of
     * throwing (which would surface as 500 rather than 403).
     */
    public boolean canAccessTenant(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) return false;
        try {
            return canAccessTenant(UUID.fromString(tenantId));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Checks if the current user is ROOT.
     */
    public boolean isRoot() {
        return getCurrentUser()
                .map(u -> u.getUserType() == UserType.ROOT)
                .orElse(false);
    }

    /**
     * Checks if the current user is the platform super-admin (ROOT).
     *
     * <p>Alias for {@link #isRoot()} exposed under the name used in GDPR-purge
     * {@code @PreAuthorize} expressions — keeps {@code @rbac.isSuperAdmin()} readable
     * at the call-site without conflating "tenant admin" with "platform owner".</p>
     */
    public boolean isSuperAdmin() {
        return isRoot();
    }

    /**
     * Checks if the current user is at least a TENANT_ADMIN.
     */
    public boolean isTenantAdmin() {
        return getCurrentUser()
                .map(u -> u.getUserType().isAtLeast(UserType.TENANT_ADMIN))
                .orElse(false);
    }

    /**
     * Checks if the current user is at least a TENANT_MEMBER (not a guest).
     */
    public boolean isMember() {
        return getCurrentUser()
                .map(u -> u.getUserType().isAtLeast(UserType.TENANT_MEMBER))
                .orElse(false);
    }

    /**
     * Checks if current user can assign a role.
     * Only ROOT and TENANT_ADMIN can assign roles.
     * TENANT_ADMIN cannot assign ROOT-level roles.
     */
    public boolean canAssignRole(UUID roleId) {
        User currentUser = getCurrentUser().orElse(null);
        if (currentUser == null) return false;

        if (currentUser.getUserType() == UserType.ROOT) return true;

        if (currentUser.getUserType() == UserType.TENANT_ADMIN) {
            return hasPermission(currentUser, "user_role:assign");
        }

        return false;
    }

    /**
     * Checks if current user can invite guests.
     */
    public boolean canInviteGuests() {
        User currentUser = getCurrentUser().orElse(null);
        if (currentUser == null) return false;
        return hasPermission(currentUser, "guest:invite");
    }

    /**
     * Checks if a permission is system-level (only ROOT).
     */
    private boolean isSystemPermission(String permission) {
        return permission != null && (
            permission.startsWith("system:") ||
            permission.equals("tenant:create")
        );
    }

    /**
     * Gets the currently authenticated user entity from the database.
     *
     * <p><b>Tenant-switcher correctness.</b> The lookup runs with the Hibernate
     * {@code tenantFilter} disabled (see {@link TenantFilterBypass}). Otherwise,
     * when a SUPER_ADMIN is browsing a foreign tenant (active {@code X-Tenant-ID}),
     * the active-tenant filter would scope this self-lookup to the foreign tenant
     * and filter out the caller's OWN row (a ROOT user lives in the system
     * tenant) — collapsing their authorities and yielding a spurious 403 on the
     * very endpoint that drives the switcher. Resolving authz is caller-scoped by
     * unique email, never a cross-tenant browse, so disabling the filter here is
     * safe; the {@code @SQLRestriction} soft-delete guard still applies.</p>
     */
    public Optional<User> getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth.getName() == null) {
            return Optional.empty();
        }

        String email = auth.getName();
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> userRepository.findByEmail(email));
    }

    /**
     * Returns the {@code tenant_id} of the currently authenticated principal, or
     * {@link Optional#empty()} if there is no authenticated user (or the user has
     * no tenant attached, e.g. ROOT/SUPER_ADMIN).
     *
     * <p>This helper exists so application/controller code can derive the caller's
     * tenant scope WITHOUT importing {@code entity.User} — the JPA entity is kept
     * inside the {@code security..} package per the hexagonal-boundary ratchet
     * enforced by {@code UserDomainBoundaryTest}. See
     * {@code ANALYSIS_2026-05-02_USER_DOMAIN_AND_JWT_ROTATION.md}.
     */
    public Optional<UUID> getCurrentUserTenantId() {
        return getCurrentUser()
                .map(User::getTenant)
                .map(t -> t.getId());
    }

    /**
     * Returns the {@code id} of the currently authenticated principal, or
     * {@link Optional#empty()} if unauthenticated.
     *
     * <p>Exposed (like {@link #getCurrentUserTenantId()}) so application /
     * controller code can attribute audit rows to the acting user WITHOUT
     * importing {@code entity.User} — keeping the JPA entity behind the
     * {@code security..} boundary ratchet ({@code UserDomainBoundaryTest}).</p>
     */
    public Optional<UUID> getCurrentUserId() {
        return getCurrentUser().map(User::getId);
    }
}
