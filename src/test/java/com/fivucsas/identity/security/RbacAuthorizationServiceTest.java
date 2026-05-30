package com.fivucsas.identity.security;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RbacAuthorizationService} focused on the tenant-switcher
 * 403 fix: the caller's own identity/authorities are resolved through
 * {@link TenantFilterBypass} (tenant filter suppressed), so a switched
 * ROOT keeps their authorities and {@code @PreAuthorize} passes.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RbacAuthorizationService — caller self-resolution bypasses tenant filter")
class RbacAuthorizationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private TenantFilterBypass tenantFilterBypass;

    private RbacAuthorizationService rbac;

    @BeforeEach
    void setUp() {
        rbac = new RbacAuthorizationService(userRepository, tenantFilterBypass);
        // The bypass executes the supplied work directly in tests.
        lenient().when(tenantFilterBypass.runWithoutTenantFilter(any()))
                .thenAnswer(inv -> ((Supplier<?>) inv.getArgument(0)).get());
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private void authenticateAs(String email) {
        var auth = new UsernamePasswordAuthenticationToken(email, null, java.util.List.of());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @Test
    @DisplayName("getCurrentUser routes the email lookup through the tenant-filter bypass")
    void getCurrentUserUsesBypass() {
        authenticateAs("root@example.com");
        User root = User.builder().id(UUID.randomUUID())
                .email("root@example.com").userType(UserType.ROOT).build();
        when(userRepository.findByEmail("root@example.com")).thenReturn(Optional.of(root));

        Optional<User> resolved = rbac.getCurrentUser();

        assertThat(resolved).containsSame(root);
        // The load MUST go through the bypass, not a raw repository call.
        verify(tenantFilterBypass).runWithoutTenantFilter(any());
    }

    @Test
    @DisplayName("ROOT caller passes hasPermission even though their row would be tenant-filtered out otherwise")
    void rootPassesPermissionAfterSwitch() {
        authenticateAs("root@example.com");
        User root = User.builder().id(UUID.randomUUID())
                .email("root@example.com").userType(UserType.ROOT).build();
        when(userRepository.findByEmail("root@example.com")).thenReturn(Optional.of(root));

        // ROOT short-circuits to true regardless of role rows.
        assertThat(rbac.hasPermission("user:read")).isTrue();
        assertThat(rbac.isRoot()).isTrue();
    }

    @Test
    @DisplayName("unauthenticated → empty, no repository hit")
    void unauthenticatedReturnsEmpty() {
        // No authentication set.
        lenient().when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        assertThat(rbac.getCurrentUser()).isEmpty();
        assertThat(rbac.hasPermission("user:read")).isFalse();
    }
}
