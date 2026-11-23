package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.PermissionRepositoryPort;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.domain.exception.SystemRoleModificationException;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.UserRoleRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * #242 - deleting a role must not leave user_roles rows pointing at a
 * soft-deleted row: with {@code @SQLRestriction("deleted_at IS NULL")} on Role,
 * such a grant can no longer be loaded or revoked through the API. The delete
 * clears the assignments in the same transaction.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("#242 - role deletion clears the grants in the same transaction")
class ManageRoleServiceDeleteRoleTest {

    @Mock private RoleRepositoryPort roleRepository;
    @Mock private PermissionRepositoryPort permissionRepository;
    @Mock private JpaTenantRepository tenantRepository;
    @Mock private UserRoleRepository userRoleRepository;

    @InjectMocks private ManageRoleService service;

    private Role role(UUID id, boolean systemRole) {
        return Role.builder()
                .id(id)
                .name("TENANT_EDITOR")
                .isSystemRole(systemRole)
                .active(true)
                .build();
    }

    @Test
    void deleteRole_clearsAssignmentsAndSoftDeletes() {
        UUID id = UUID.randomUUID();
        Role role = role(id, false);
        when(roleRepository.findById(id)).thenReturn(Optional.of(role));

        service.deleteRole(id.toString());

        verify(userRoleRepository).deleteAllByRoleId(id);
        verify(roleRepository).save(role);
        assertThat(role.isDeleted()).isTrue();
        assertThat(role.isActive()).isFalse();
    }

    @Test
    void deleteRole_systemRole_refusesAndKeepsAssignments() {
        UUID id = UUID.randomUUID();
        Role role = role(id, true);
        when(roleRepository.findById(id)).thenReturn(Optional.of(role));

        assertThatThrownBy(() -> service.deleteRole(id.toString()))
                .isInstanceOf(SystemRoleModificationException.class);

        verifyNoInteractions(userRoleRepository);
        assertThat(role.isDeleted()).isFalse();
    }
}