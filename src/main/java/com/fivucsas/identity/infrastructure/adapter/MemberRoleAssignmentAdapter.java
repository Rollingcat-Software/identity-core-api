package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.MemberRoleAssignmentPort;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.repository.RoleRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Infrastructure adapter implementing {@link MemberRoleAssignmentPort}
 * (default-role-on-join, V64).
 *
 * <p>Lives in {@code infrastructure.adapter} — an allow-listed package for
 * touching {@code entity.User}/{@code entity.Role} — so the application-layer
 * {@code RegisterUserService} can assign a default role without importing the
 * JPA role model itself.</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MemberRoleAssignmentAdapter implements MemberRoleAssignmentPort {

    /**
     * Seeded baseline role used when a tenant has not configured an explicit
     * {@code default_member_role}. {@code "USER"} is seeded by V3 under the
     * system tenant and {@code "TENANT_VIEWER"} per V10 — we prefer a tenant's
     * own role named USER, then any seeded USER, falling back gracefully.
     */
    private static final String FALLBACK_ROLE_NAME = "USER";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    @Transactional
    public String assignDefaultMemberRole(UUID userId, UUID tenantId) {
        try {
            Optional<User> maybeUser = userRepository.findById(userId);
            if (maybeUser.isEmpty()) {
                log.warn("default-role-on-join: user {} not found; skipping role assignment", userId);
                return null;
            }
            User user = maybeUser.get();

            String configuredRoleName = user.getTenant() != null
                    ? user.getTenant().getDefaultMemberRole()
                    : null;

            Role role = resolveRole(tenantId, configuredRoleName);
            if (role == null) {
                log.warn("default-role-on-join: no default member role resolvable for tenant {} "
                        + "(configured='{}', fallback='{}'); user {} joins with no role",
                        tenantId, configuredRoleName, FALLBACK_ROLE_NAME, userId);
                return null;
            }

            // Idempotent — don't duplicate an existing assignment.
            if (userRoleRepository.existsByIdUserIdAndIdRoleId(userId, role.getId())) {
                return role.getName();
            }

            UserRole assignment = UserRole.create(user, role, null);
            userRoleRepository.save(assignment);
            log.info("default-role-on-join: assigned role '{}' to user {} in tenant {}",
                    role.getName(), userId, tenantId);
            return role.getName();
        } catch (Exception e) {
            // Never let a role-assignment hiccup roll back a successful
            // registration — log and move on.
            log.warn("default-role-on-join: failed to assign default role to user {} in tenant {}: {}",
                    userId, tenantId, e.getMessage());
            return null;
        }
    }

    /**
     * Resolves the role to assign: the tenant's configured role by name (if it
     * exists), else the seeded baseline {@code USER} role for this tenant, else
     * the global/system {@code USER} role.
     */
    private Role resolveRole(UUID tenantId, String configuredRoleName) {
        if (configuredRoleName != null && !configuredRoleName.isBlank()) {
            Optional<Role> configured = roleRepository
                    .findByTenantIdAndNameAndDeletedAtIsNull(tenantId, configuredRoleName.trim());
            if (configured.isPresent()) {
                return configured.get();
            }
            log.warn("default-role-on-join: configured default role '{}' not found for tenant {}; "
                    + "falling back to '{}'", configuredRoleName, tenantId, FALLBACK_ROLE_NAME);
        }
        // Prefer a tenant-scoped baseline role, then any seeded baseline.
        return roleRepository.findByTenantIdAndNameAndDeletedAtIsNull(tenantId, FALLBACK_ROLE_NAME)
                .or(() -> roleRepository.findByNameAndDeletedAtIsNull(FALLBACK_ROLE_NAME))
                .orElse(null);
    }
}
