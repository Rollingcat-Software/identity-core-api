package com.fivucsas.identity.security;

import com.fivucsas.identity.entity.Permission;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserRole;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Custom UserDetailsService implementation for loading user-specific data.
 * Integrates with Spring Security's authentication mechanism.
 *
 * Loads user's roles and permissions from the database for RBAC.
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

        // Load authorities (roles and permissions) from database
        Set<GrantedAuthority> authorities = loadUserAuthorities(user.getId());

        log.debug("Loaded {} authorities for user {}", authorities.size(), email);

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPasswordHash())
                .authorities(authorities)
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(!isUserActive(user))
                .build();
    }

    /**
     * Loads all authorities (roles and permissions) for a user from the database.
     *
     * @param userId the user's ID
     * @return set of granted authorities
     */
    private Set<GrantedAuthority> loadUserAuthorities(java.util.UUID userId) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // Load active user roles with permissions
        List<UserRole> userRoles = userRoleRepository.findActiveUserRolesWithPermissions(
                userId, Instant.now()
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

        // If no roles found, add a basic USER role as fallback
        if (authorities.isEmpty()) {
            log.warn("No roles found for user {}, adding default ROLE_USER", userId);
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return authorities;
    }

    private boolean isUserActive(User user) {
        return user.getStatus() != null &&
               user.getStatus().name().equals("ACTIVE");
    }
}
