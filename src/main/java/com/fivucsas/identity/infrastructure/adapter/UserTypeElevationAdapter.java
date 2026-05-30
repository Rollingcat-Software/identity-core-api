package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.UserTypeElevationPort;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Infrastructure adapter implementing {@link UserTypeElevationPort} — the
 * ongoing elevate-on-grant sync that keeps {@code users.user_type} aligned with
 * the ROOT / TENANT_ADMIN RBAC roles (role / user_type unification, see
 * {@code docs/IDENTITY_ROLE_UNIFICATION.md}).
 *
 * <p>Lives in {@code infrastructure.adapter} — an allow-listed package for
 * touching {@code entity.User} — so the application-layer
 * {@code ManageUserRoleService} can elevate the tier without importing the JPA
 * user model itself.</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class UserTypeElevationAdapter implements UserTypeElevationPort {

    /** The seeded global ROOT role (renamed from SUPER_ADMIN by V69). */
    private static final UUID ROOT_ROLE_ID =
            UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final String ROOT_ROLE_NAME = "ROOT";
    private static final String TENANT_ADMIN_ROLE_NAME = "TENANT_ADMIN";

    private final UserRepository userRepository;

    @Override
    @Transactional
    public void elevateForGrantedRole(UUID userId, UUID roleId, String roleName) {
        try {
            UserType targetTier = tierForRole(roleId, roleName);
            if (targetTier == null) {
                // Plain permission role — the tier is unaffected.
                return;
            }

            Optional<User> maybeUser = userRepository.findById(userId);
            if (maybeUser.isEmpty()) {
                log.warn("user_type elevate-on-grant: user {} not found; skipping", userId);
                return;
            }
            User user = maybeUser.get();

            UserType current = user.getUserType();
            // ELEVATE-ONLY: never lower an existing higher (or equal) tier.
            if (current != null && current.isAtLeast(targetTier)) {
                return;
            }

            user.setUserType(targetTier);
            userRepository.save(user);
            log.info("user_type elevate-on-grant: user {} elevated {} -> {} after grant of role '{}' ({})",
                    userId, current, targetTier, roleName, roleId);
        } catch (Exception e) {
            // A tier-sync hiccup must never roll back the role assignment.
            log.warn("user_type elevate-on-grant: failed to sync user {} for role '{}' ({}): {}",
                    userId, roleName, roleId, e.getMessage());
        }
    }

    /**
     * Maps a granted role to the platform tier it confers, or {@code null} if the
     * role is a plain permission role that does not encode a tier.
     */
    private static UserType tierForRole(UUID roleId, String roleName) {
        if (ROOT_ROLE_ID.equals(roleId)
                || (roleName != null && ROOT_ROLE_NAME.equalsIgnoreCase(roleName.trim()))) {
            return UserType.ROOT;
        }
        if (roleName != null && TENANT_ADMIN_ROLE_NAME.equalsIgnoreCase(roleName.trim())) {
            return UserType.TENANT_ADMIN;
        }
        return null;
    }
}
