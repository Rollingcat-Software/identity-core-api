package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.ChangePasswordUseCase;
import com.fivucsas.identity.application.port.input.ManageUserUseCase;
import com.fivucsas.identity.application.port.output.GuestInvitationRepositoryPort;
import com.fivucsas.identity.application.port.output.UserSettingsRepositoryPort;
import com.fivucsas.identity.application.service.GuestLifecycleService;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.entity.UserSettings;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Authz IDOR fix (2026-06-07): user-settings cross-tenant access guard
 * ({@code UserController.assertCanAccessUserSettings}).
 *
 * <p>The {@code @PreAuthorize("hasPermission(#userId, 'user_settings', ...) or
 * isCurrentUser(#userId)")} SpEL does NOT do object-level authz — the
 * {@code RbacPermissionEvaluator} ignores the {@code #userId} target and only
 * checks whether the caller holds {@code user_settings:read/write}, which a
 * TENANT_ADMIN holds implicitly for EVERY tenant. The service-layer guard is what
 * actually stops a TENANT_ADMIN of tenant A from reading/writing the (incl.
 * security) settings of a user in tenant B.</p>
 *
 * <p>Pure-Mockito unit test (no Spring, no Docker): the controller's settings
 * methods are invoked directly with mocked collaborators.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("UserController — user-settings cross-tenant authz guard")
class UserSettingsAuthzTest {

    @Mock private ManageUserUseCase manageUserUseCase;
    @Mock private ChangePasswordUseCase changePasswordUseCase;
    @Mock private UserSettingsRepositoryPort userSettingsRepository;
    @Mock private GuestLifecycleService guestLifecycleService;
    @Mock private GuestInvitationRepositoryPort invitationRepository;
    @Mock private RbacAuthorizationService rbacService;
    @Mock private TenantScopeResolver tenantScopeResolver;
    @Mock private JpaTenantRepository tenantRepository;
    @Mock private UserRepository userRepository;

    private UserController controller;

    private final UUID callerId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        controller = new UserController(
                manageUserUseCase, changePasswordUseCase, userSettingsRepository,
                guestLifecycleService, invitationRepository, rbacService,
                tenantScopeResolver, tenantRepository, userRepository);
        when(rbacService.getCurrentUserId()).thenReturn(Optional.of(callerId));
    }

    @Test
    @DisplayName("getUserSettings → 403 when an admin reads a user in a tenant they cannot manage (cross-tenant IDOR)")
    void getUserSettings_WhenCrossTenantTarget_ShouldThrowUnauthorized() {
        UUID targetUserId = UUID.randomUUID();
        UUID foreignTenantId = UUID.randomUUID();
        when(userRepository.findTenantIdById(targetUserId))
                .thenReturn(Optional.of(foreignTenantId));
        when(tenantScopeResolver.canAccessTenant(foreignTenantId)).thenReturn(false);

        assertThatExceptionOfType(UnauthorizedException.class)
                .isThrownBy(() -> controller.getUserSettings(targetUserId.toString()));

        verify(userSettingsRepository, never()).findByUserId(any());
    }

    @Test
    @DisplayName("getSecuritySettings → 403 cross-tenant (worst case: reading another tenant's SECURITY settings)")
    void getSecuritySettings_WhenCrossTenantTarget_ShouldThrowUnauthorized() {
        UUID targetUserId = UUID.randomUUID();
        UUID foreignTenantId = UUID.randomUUID();
        when(userRepository.findTenantIdById(targetUserId))
                .thenReturn(Optional.of(foreignTenantId));
        when(tenantScopeResolver.canAccessTenant(foreignTenantId)).thenReturn(false);

        assertThatExceptionOfType(UnauthorizedException.class)
                .isThrownBy(() -> controller.getSecuritySettings(targetUserId.toString()));

        verify(userSettingsRepository, never()).findByUserId(any());
    }

    @Test
    @DisplayName("updateUserSettings → 403 when an admin writes a user in a tenant they cannot manage")
    void updateUserSettings_WhenCrossTenantTarget_ShouldThrowUnauthorizedAndNotSave() {
        UUID targetUserId = UUID.randomUUID();
        UUID foreignTenantId = UUID.randomUUID();
        when(userRepository.findTenantIdById(targetUserId))
                .thenReturn(Optional.of(foreignTenantId));
        when(tenantScopeResolver.canAccessTenant(foreignTenantId)).thenReturn(false);

        assertThatExceptionOfType(UnauthorizedException.class)
                .isThrownBy(() -> controller.updateUserSettings(
                        targetUserId.toString(), Map.of("security", Map.of("twoFactorEnabled", true))));

        verify(userSettingsRepository, never()).save(any());
    }

    @Test
    @DisplayName("getUserSettings → owner may read their OWN settings (self-access allowed)")
    void getUserSettings_WhenOwner_ShouldReturnSettings() {
        UserSettings settings = UserSettings.builder()
                .userId(callerId)
                .settings(Map.of("appearance", Map.of("theme", "dark")))
                .build();
        when(userSettingsRepository.findByUserId(callerId)).thenReturn(Optional.of(settings));

        ResponseEntity<Map<String, Object>> resp =
                controller.getUserSettings(callerId.toString());

        assertThat(resp.getStatusCode().value()).isEqualTo(200);
        assertThat(resp.getBody()).containsKey("appearance");
        // The target tenant must NOT even be resolved for a self-read.
        verify(userRepository, never()).findTenantIdById(any());
    }

    @Test
    @DisplayName("getUserSettings → admin within the target's tenant may read another user's settings")
    void getUserSettings_WhenAdminInTenant_ShouldReturnSettings() {
        UUID targetUserId = UUID.randomUUID();
        UUID sharedTenantId = UUID.randomUUID();
        when(userRepository.findTenantIdById(targetUserId))
                .thenReturn(Optional.of(sharedTenantId));
        when(tenantScopeResolver.canAccessTenant(sharedTenantId)).thenReturn(true);
        when(userSettingsRepository.findByUserId(targetUserId)).thenReturn(Optional.empty());

        ResponseEntity<Map<String, Object>> resp =
                controller.getUserSettings(targetUserId.toString());

        // Empty → default settings (200), guard passed.
        assertThat(resp.getStatusCode().value()).isEqualTo(200);
        assertThat(resp.getBody()).isNotNull();
    }
}
