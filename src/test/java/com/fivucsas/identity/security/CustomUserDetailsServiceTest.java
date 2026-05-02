package com.fivucsas.identity.security;

import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.UserRoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Regression test guarding the wiring of {@link CustomUserDetails} as the
 * authenticated principal. Before the fix, this service returned Spring's
 * stock {@code org.springframework.security.core.userdetails.User}, causing
 * every {@code instanceof CustomUserDetails} downcast in
 * {@code TenantBindFromAuthFilter}, {@code AuthorizationService}, and
 * {@code AuditLoggingAspect} to silently no-op — leaving PR #54's
 * cross-tenant defence inert in production.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("CustomUserDetailsService — principal type contract")
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserRoleRepository userRoleRepository;

    @InjectMocks
    private CustomUserDetailsService service;

    private UUID userId;
    private UUID tenantId;
    private Tenant tenant;
    private User activeUser;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        tenantId = UUID.randomUUID();
        tenant = Tenant.builder().id(tenantId).build();
        activeUser = User.builder()
                .id(userId)
                .email("alice@example.com")
                .passwordHash("$2a$10$dummyhashfortesting.................................")
                .tenant(tenant)
                .userType(UserType.TENANT_MEMBER)
                .status(UserStatus.ACTIVE)
                .isActive(true)
                .build();
    }

    @Test
    @DisplayName("active user → returns CustomUserDetails carrying userId + tenantId")
    void activeUser_returnsCustomUserDetailsWithIds() {
        when(userRepository.findByEmail("alice@example.com"))
                .thenReturn(Optional.of(activeUser));
        when(userRoleRepository.findActiveUserRolesWithPermissions(any(UUID.class), any(Instant.class)))
                .thenReturn(Collections.emptyList());

        UserDetails ud = service.loadUserByUsername("alice@example.com");

        assertThat(ud)
                .as("must be CustomUserDetails so TenantBindFromAuthFilter can downcast")
                .isInstanceOf(CustomUserDetails.class);

        CustomUserDetails details = (CustomUserDetails) ud;
        assertThat(details.getUserId()).isEqualTo(userId);
        assertThat(details.getTenantId()).isEqualTo(tenantId);
        assertThat(details.getEmail()).isEqualTo("alice@example.com");
        assertThat(details.getUsername()).isEqualTo("alice@example.com");
        assertThat(details.isEnabled()).isTrue();
        assertThat(details.getAuthorities())
                .extracting("authority")
                .contains("USER_TYPE_TENANT_MEMBER");
    }

    @Test
    @DisplayName("inactive user → returns CustomUserDetails with enabled=false")
    void inactiveUser_returnsDisabledCustomUserDetails() {
        User suspended = User.builder()
                .id(userId)
                .email("alice@example.com")
                .passwordHash("$2a$10$dummyhashfortesting.................................")
                .tenant(tenant)
                .userType(UserType.TENANT_MEMBER)
                .status(UserStatus.SUSPENDED)
                .isActive(false)
                .build();
        when(userRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(suspended));
        when(userRoleRepository.findActiveUserRolesWithPermissions(any(UUID.class), any(Instant.class)))
                .thenReturn(Collections.emptyList());

        UserDetails ud = service.loadUserByUsername("alice@example.com");

        assertThat(ud).isInstanceOf(CustomUserDetails.class);
        assertThat(ud.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("expired guest → returns CustomUserDetails (disabled, no authorities) — preserves prior reject semantics")
    void expiredGuest_returnsDisabledCustomUserDetails() {
        User guest = User.builder()
                .id(userId)
                .email("guest@example.com")
                .passwordHash("$2a$10$dummyhashfortesting.................................")
                .tenant(tenant)
                .userType(UserType.GUEST)
                .status(UserStatus.ACTIVE)
                .isActive(true)
                .expiresAt(Instant.now().minusSeconds(60)) // already expired
                .build();
        when(userRepository.findByEmail("guest@example.com"))
                .thenReturn(Optional.of(guest));

        UserDetails ud = service.loadUserByUsername("guest@example.com");

        assertThat(ud)
                .as("expired branch must still return CustomUserDetails so principal type is consistent")
                .isInstanceOf(CustomUserDetails.class);
        assertThat(ud.isEnabled()).isFalse();
        assertThat(ud.getAuthorities()).isEmpty();
        assertThat(((CustomUserDetails) ud).getUserId()).isEqualTo(userId);
        assertThat(((CustomUserDetails) ud).getTenantId()).isEqualTo(tenantId);
    }

    @Test
    @DisplayName("user without tenant → CustomUserDetails.tenantId is null (filter handles)")
    void tenantlessUser_returnsCustomUserDetailsWithNullTenantId() {
        User tenantless = User.builder()
                .id(userId)
                .email("root@example.com")
                .passwordHash("$2a$10$dummyhashfortesting.................................")
                .tenant(null)
                .userType(UserType.ROOT)
                .status(UserStatus.ACTIVE)
                .isActive(true)
                .build();
        when(userRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(tenantless));
        when(userRoleRepository.findActiveUserRolesWithPermissions(any(UUID.class), any(Instant.class)))
                .thenReturn(Collections.emptyList());

        UserDetails ud = service.loadUserByUsername("root@example.com");

        assertThat(ud).isInstanceOf(CustomUserDetails.class);
        assertThat(((CustomUserDetails) ud).getTenantId()).isNull();
    }

    @Test
    @DisplayName("unknown email → UsernameNotFoundException")
    void unknownEmail_throws() {
        when(userRepository.findByEmail("ghost@example.com"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.loadUserByUsername("ghost@example.com"))
                .isInstanceOf(UsernameNotFoundException.class);
    }
}
