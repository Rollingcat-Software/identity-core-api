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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies the elevate-on-grant sync wiring in {@link ManageUserRoleService}:
 * assigning a role routes the granted role's id + name to
 * {@link UserTypeElevationPort#elevateForGrantedRole} (the ongoing half of the
 * role / user_type unification — see docs/IDENTITY_ROLE_UNIFICATION.md).
 *
 * <p>The tier-mapping + elevate-only semantics themselves are unit-tested in
 * {@code UserTypeElevationAdapterTest}; here we only assert the choke-point
 * service invokes the port with the correct arguments on every assignment.</p>
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
    @DisplayName("assignRole → port.elevateForGrantedRole called with the granted role's id + name")
    void assignRoleTriggersElevation() {
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

        // The assignment is persisted AND the tier sync is invoked with the
        // granted role's identity so the adapter can elevate user_type → ROOT.
        verify(userRoleRepository).save(any());
        verify(userTypeElevationPort).elevateForGrantedRole(userId, ROOT_ROLE_ID, "ROOT");
    }
}
