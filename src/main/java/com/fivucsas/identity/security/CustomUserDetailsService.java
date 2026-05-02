package com.fivucsas.identity.security;

import com.fivucsas.identity.entity.Permission;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Custom UserDetailsService implementation for loading user-specific data.
 * Integrates with Spring Security's authentication mechanism.
 *
 * <p>Loads user's roles and permissions from the database for RBAC,
 * including UserType-based authorities for hierarchical access control.
 *
 * <p>Authority format:
 * <ul>
 *   <li>{@code ROLE_X} for role-based authorities</li>
 *   <li>{@code resource:action} for permission-based authorities</li>
 *   <li>{@code USER_TYPE_X} for user type hierarchy</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.debug("Loading user by email: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        // Check if guest account has expired
        if (user.isExpired()) {
            log.warn("Expired guest user attempted login: {}", email);
            // Disabled CustomUserDetails — Spring's DaoAuthenticationProvider treats
            // !isEnabled() as a hard reject (DisabledException), preserving the
            // previous .accountExpired(true).disabled(true) semantics. Returning
            // CustomUserDetails (instead of Spring's stock User) is required so
            // TenantBindFromAuthFilter / AuthorizationService / AuditLoggingAspect
            // can downcast the principal — the silent no-op fixed by this PR.
            return new CustomUserDetails(
                    user.getId(),
                    user.getEmail(),
                    user.getPasswordHash(),
                    extractTenantId(user),
                    false,                               // enabled = false → expired/disabled
                    Collections.<GrantedAuthority>emptySet()
            );
        }

        // Load authorities (roles, permissions, and user type)
        Set<GrantedAuthority> authorities = loadUserAuthorities(user);

        log.debug("Loaded {} authorities for user {} (type: {})",
                authorities.size(), email, user.getUserType());

        return new CustomUserDetails(
                user.getId(),
                user.getEmail(),
                user.getPasswordHash(),
                extractTenantId(user),
                isUserActive(user),
                authorities
        );
    }

    private static UUID extractTenantId(User user) {
        Tenant tenant = user.getTenant();
        return tenant != null ? tenant.getId() : null;
    }

    /**
     * Loads all authorities for a user including:
     * - User type authority (USER_TYPE_ROOT, USER_TYPE_TENANT_ADMIN, etc.)
     * - Role authorities (ROLE_SUPER_ADMIN, ROLE_USER, etc.)
     * - Permission authorities (user:read, biometric:enroll, etc.)
     */
    private Set<GrantedAuthority> loadUserAuthorities(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // Add user type as authority for hierarchy-based checks
        authorities.add(new SimpleGrantedAuthority("USER_TYPE_" + user.getUserType().name()));

        // ROOT gets special role authorities - permission bypass is handled at service level
        if (user.getUserType() == UserType.ROOT) {
            authorities.add(new SimpleGrantedAuthority("ROLE_ROOT"));
            authorities.add(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"));
        }

        // Load active user roles with permissions
        List<UserRole> userRoles = userRoleRepository.findActiveUserRolesWithPermissions(
                user.getId(), Instant.now()
        );

        for (UserRole userRole : userRoles) {
            Role role = userRole.getRole();

            // Add role as authority (ROLE_SUPER_ADMIN, ROLE_USER, etc.)
            String roleAuthority = "ROLE_" + role.getName();
            authorities.add(new SimpleGrantedAuthority(roleAuthority));
            log.trace("Added role authority: {}", roleAuthority);

            // Add all permissions from the role (user:read, biometric:enroll, etc.)
            for (Permission permission : role.getPermissions()) {
                String permissionAuthority = permission.getAuthorityName();
                authorities.add(new SimpleGrantedAuthority(permissionAuthority));
                log.trace("Added permission authority: {}", permissionAuthority);
            }
        }

        // If no roles found and not ROOT/GUEST, add a basic USER role as fallback
        if (userRoles.isEmpty() && user.getUserType() != UserType.ROOT
                && user.getUserType() != UserType.GUEST) {
            log.warn("No roles found for user {}, adding default ROLE_USER", user.getId());
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return authorities;
    }

    private boolean isUserActive(User user) {
        return user.getStatus() != null &&
               user.getStatus().name().equals("ACTIVE");
    }
}
