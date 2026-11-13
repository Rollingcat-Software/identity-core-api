package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.query.GetRoleUsersQuery;
import com.fivucsas.identity.application.dto.response.UserRoleResponse;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserTypeElevationPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@code GET /api/v1/users/{userId}/roles/all/{roleId}} lists the holders of a role. A
 * role id can name a global role held in several tenants, so a scoped caller must only
 * reach the tenant-predicated query.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Role holders are limited to the caller's tenant scope")
class ManageUserRoleServiceRoleUsersScopeTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepositoryPort roleRepository;
    @Mock private UserRoleRepositoryPort userRoleRepository;
    @Mock private UserTypeElevationPort userTypeElevationPort;

    @InjectMocks private ManageUserRoleService service;

    private static final UUID TENANT_A = UUID.fromString("0a0a0a0a-0000-4000-8000-00000000000a");
    private static final UUID TENANT_B = UUID.fromString("0b0b0b0b-0000-4000-8000-00000000000b");
    private static final UUID GLOBAL_ROLE = UUID.fromString("20000000-0000-4000-8000-000000000002");

    private UserRole holderInA;
    private UserRole holderInB;

    @BeforeEach
    void setUp() {
        Role role = Role.builder().id(GLOBAL_ROLE).name("GLOBAL").build();
        when(roleRepository.findById(GLOBAL_ROLE)).thenReturn(Optional.of(role));
        holderInA = UserRole.create(user(TENANT_A, "a@example.test"), role, null, null);
        holderInB = UserRole.create(user(TENANT_B, "b@example.test"), role, null, null);
    }

    private static User user(UUID tenantId, String email) {
        return User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .firstName("X")
                .lastName("Y")
                .tenant(Tenant.builder().id(tenantId).name("t").build())
                .build();
    }

    private List<UserRoleResponse> holders(UUID scope) {
        return service.getRoleUsers(GetRoleUsersQuery.builder()
                .roleId(GLOBAL_ROLE.toString())
                .tenantScope(scope)
                .build());
    }

    @Test
    void getRoleUsers_WhenScopedToTenantA_ShouldQueryOnlyTenantA() {
        when(userRoleRepository.findByRoleIdWithUserInTenant(GLOBAL_ROLE, TENANT_A)).thenReturn(List.of(holderInA));

        assertThat(holders(TENANT_A)).extracting(UserRoleResponse::getUserEmail)
                .containsExactly("a@example.test");
        verify(userRoleRepository, never()).findByRoleIdWithUser(any());
    }

    @Test
    void getRoleUsers_WhenScopeIsFailClosed_ShouldNeverRunTheUnscopedQuery() {
        when(userRoleRepository.findByRoleIdWithUserInTenant(GLOBAL_ROLE, TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE))
                .thenReturn(List.of());

        assertThat(holders(TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE)).isEmpty();
        verify(userRoleRepository, never()).findByRoleIdWithUser(any());
    }

    @Test
    void getRoleUsers_WhenUnrestricted_ShouldReturnEveryHolder() {
        when(userRoleRepository.findByRoleIdWithUser(GLOBAL_ROLE)).thenReturn(List.of(holderInA, holderInB));

        assertThat(holders(null)).extracting(UserRoleResponse::getUserEmail)
                .containsExactlyInAnyOrder("a@example.test", "b@example.test");
    }
}
