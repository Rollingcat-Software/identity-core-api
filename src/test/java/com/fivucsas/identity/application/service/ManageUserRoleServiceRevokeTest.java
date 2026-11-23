package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RevokeRoleFromUserCommand;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserTypeElevationPort;
import com.fivucsas.identity.domain.exception.RoleNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * #242 - after Role gained @SQLRestriction("deleted_at IS NULL"), findById no
 * longer sees a soft-deleted role. The revoke endpoint must still remove a
 * legacy user_roles grant that points at one; it verifies the assignment, not
 * the live role.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("#242 - revoking an assignment of a soft-deleted role")
class ManageUserRoleServiceRevokeTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepositoryPort roleRepository;
    @Mock private UserRoleRepositoryPort userRoleRepository;
    @Mock private UserTypeElevationPort userTypeElevationPort;

    @InjectMocks private ManageUserRoleService service;

    private RevokeRoleFromUserCommand command(UUID userId, UUID roleId) {
        return RevokeRoleFromUserCommand.builder()
                .userId(userId.toString())
                .roleId(roleId.toString())
                .build();
    }

    @Test
    void revokeRoleFromUser_softDeletedRoleWithExistingGrant_stillRevokes() {
        UUID userId = UUID.randomUUID();
        UUID roleId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.of(org.mockito.Mockito.mock(
                com.fivucsas.identity.entity.User.class)));
        // The role is soft-deleted and therefore invisible to findById; the
        // service must not consult it. The grant still exists and is removable.
        when(userRoleRepository.existsByIdUserIdAndIdRoleId(userId, roleId)).thenReturn(true);

        service.revokeRoleFromUser(command(userId, roleId));

        verify(roleRepository, never()).findById(any());
        verify(userRoleRepository).deleteByUserIdAndRoleId(userId, roleId);
    }

    @Test
    void revokeRoleFromUser_missingGrant_throwsRoleNotFound() {
        UUID userId = UUID.randomUUID();
        UUID roleId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.of(org.mockito.Mockito.mock(
                com.fivucsas.identity.entity.User.class)));
        when(userRoleRepository.existsByIdUserIdAndIdRoleId(userId, roleId)).thenReturn(false);

        assertThatThrownBy(() -> service.revokeRoleFromUser(command(userId, roleId)))
                .isInstanceOf(RoleNotFoundException.class);

        verify(userRoleRepository, never()).deleteByUserIdAndRoleId(any(), any());
        verify(roleRepository, never()).findById(any());
    }
}