package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.repository.RoleRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.UserRoleRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("MemberRoleAssignmentAdapter Tests (default-role-on-join V64)")
class MemberRoleAssignmentAdapterTest {

    private static final UUID TENANT_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID USER_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private UserRoleRepository userRoleRepository;

    @InjectMocks private MemberRoleAssignmentAdapter adapter;

    private User userWithTenant(String defaultMemberRole) {
        Tenant tenant = Tenant.builder()
                .id(TENANT_ID)
                .name("Acme")
                .slug("acme")
                .contactEmail("admin@acme.com")
                .defaultMemberRole(defaultMemberRole)
                .build();
        return User.builder().id(USER_ID).email("joiner@acme.com").tenant(tenant).build();
    }

    private Role role(String name) {
        return Role.builder().id(UUID.randomUUID()).name(name)
                .tenant(Tenant.builder().id(TENANT_ID).name("Acme").slug("acme")
                        .contactEmail("a@acme.com").build())
                .build();
    }

    @Test
    @DisplayName("assigns the tenant's configured default role when present")
    void assignsConfiguredRole() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(userWithTenant("ENGINEER")));
        Role engineer = role("ENGINEER");
        when(roleRepository.findByTenantIdAndNameAndDeletedAtIsNull(TENANT_ID, "ENGINEER"))
                .thenReturn(Optional.of(engineer));
        when(userRoleRepository.existsByIdUserIdAndIdRoleId(USER_ID, engineer.getId())).thenReturn(false);

        String assigned = adapter.assignDefaultMemberRole(USER_ID, TENANT_ID);

        assertThat(assigned).isEqualTo("ENGINEER");
        ArgumentCaptor<UserRole> captor = ArgumentCaptor.forClass(UserRole.class);
        verify(userRoleRepository).save(captor.capture());
        assertThat(captor.getValue().getRoleId()).isEqualTo(engineer.getId());
    }

    @Test
    @DisplayName("falls back to the seeded baseline USER role when none configured")
    void fallsBackToBaselineRole() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(userWithTenant(null)));
        Role userRole = role("USER");
        when(roleRepository.findByTenantIdAndNameAndDeletedAtIsNull(TENANT_ID, "USER"))
                .thenReturn(Optional.of(userRole));
        when(userRoleRepository.existsByIdUserIdAndIdRoleId(USER_ID, userRole.getId())).thenReturn(false);

        String assigned = adapter.assignDefaultMemberRole(USER_ID, TENANT_ID);

        assertThat(assigned).isEqualTo("USER");
        verify(userRoleRepository).save(any(UserRole.class));
    }

    @Test
    @DisplayName("idempotent — does not duplicate an existing assignment")
    void idempotentWhenAlreadyAssigned() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(userWithTenant("USER")));
        Role userRole = role("USER");
        when(roleRepository.findByTenantIdAndNameAndDeletedAtIsNull(TENANT_ID, "USER"))
                .thenReturn(Optional.of(userRole));
        when(userRoleRepository.existsByIdUserIdAndIdRoleId(USER_ID, userRole.getId())).thenReturn(true);

        String assigned = adapter.assignDefaultMemberRole(USER_ID, TENANT_ID);

        assertThat(assigned).isEqualTo("USER");
        verify(userRoleRepository, never()).save(any());
    }

    @Test
    @DisplayName("no-op (null) when no role can be resolved — never throws")
    void noOpWhenNoRoleResolvable() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(userWithTenant(null)));
        when(roleRepository.findByTenantIdAndNameAndDeletedAtIsNull(TENANT_ID, "USER"))
                .thenReturn(Optional.empty());
        when(roleRepository.findByNameAndDeletedAtIsNull("USER")).thenReturn(Optional.empty());

        String assigned = adapter.assignDefaultMemberRole(USER_ID, TENANT_ID);

        assertThat(assigned).isNull();
        verify(userRoleRepository, never()).save(any());
    }

    @Test
    @DisplayName("falls back to baseline when the configured role name does not exist")
    void configuredRoleMissingFallsBack() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(userWithTenant("GHOST")));
        when(roleRepository.findByTenantIdAndNameAndDeletedAtIsNull(TENANT_ID, "GHOST"))
                .thenReturn(Optional.empty());
        Role userRole = role("USER");
        when(roleRepository.findByTenantIdAndNameAndDeletedAtIsNull(TENANT_ID, "USER"))
                .thenReturn(Optional.of(userRole));
        when(userRoleRepository.existsByIdUserIdAndIdRoleId(eq(USER_ID), any())).thenReturn(false);

        String assigned = adapter.assignDefaultMemberRole(USER_ID, TENANT_ID);

        assertThat(assigned).isEqualTo("USER");
    }
}
