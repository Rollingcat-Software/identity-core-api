package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.AssignRoleToUserCommand;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserTypeElevationPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies role assignment is TIER-NEUTRAL in {@link ManageUserRoleService}:
 * assigning a role grants RBAC permissions only and must NOT change the platform
 * tier ({@code users.user_type}).
 *
 * <p>SECURITY (2026-06-01, LOGIC_AUDIT P0-3 decouple): the previous
 * "elevate-on-grant" coupling — which routed the granted role to
 * {@link UserTypeElevationPort#elevateForGrantedRole} and let a role grant raise
 * the tier (e.g. the ROOT role → {@code user_type=ROOT}) — was removed. It
 * conflated the two orthogonal axes (tier = trust, role = within-tenant
 * permissions) and created the escalation surface. Platform tier is now set
 * EXPLICITLY via {@code ManageUserService.applyUserType}.
 * See docs/IDENTITY_ROLE_UNIFICATION.md.</p>
 */
@ExtendWith(MockitoExtension.class)
class ManageUserRoleServiceElevationTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepositoryPort roleRepository;
    @Mock private UserRoleRepositoryPort userRoleRepository;
    @Mock private UserTypeElevationPort userTypeElevationPort;

    @InjectMocks private ManageUserRoleService service;

    private static final UUID ROOT_ROLE_ID =
            UUID.fromString("10000000-0000-0000-0000-000000000001");

    @Test
    @DisplayName("assignRole persists the grant but does NOT change the platform tier (decoupled)")
    void assignRoleDoesNotElevateTier() {
        UUID userId = UUID.randomUUID();
        AssignRoleToUserCommand command = AssignRoleToUserCommand.builder()
                .userId(userId.toString())
                .roleId(ROOT_ROLE_ID.toString())
                .build();

        User user = User.builder().id(userId).email("ahabgu@example.com").build();
        Role role = Role.builder().id(ROOT_ROLE_ID).name("ROOT").build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(roleRepository.findByIdWithPermissions(ROOT_ROLE_ID)).thenReturn(Optional.of(role));
        when(userRoleRepository.existsByIdUserIdAndIdRoleId(userId, ROOT_ROLE_ID)).thenReturn(false);

        service.assignRoleToUser(command);

        // The RBAC grant is persisted, but the platform tier is NEVER touched by a role
        // assignment — even granting the ROOT role must not elevate user_type (P0-3 decouple).
        verify(userRoleRepository).save(any());
        verify(userTypeElevationPort, never()).elevateForGrantedRole(any(), any(), any());
    }
}
