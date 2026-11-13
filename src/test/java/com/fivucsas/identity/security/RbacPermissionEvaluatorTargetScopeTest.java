package com.fivucsas.identity.security;

import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.RoleRepository;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@code hasPermission(#id, '<Type>', '<perm>')} must honour the target id: the
 * permission alone is not enough, the target user or tenant must be inside the
 * caller's tenant (ROOT stays cross-tenant). Before this check the evaluator
 * ignored the id, and a TENANT_ADMIN, who holds every tenant-scoped permission
 * implicitly, passed for a target in any tenant.
 */
@DisplayName("RbacPermissionEvaluator: target id is scoped to the caller's tenant")
class RbacPermissionEvaluatorTargetScopeTest {

    private static final UUID TENANT_A = UUID.fromString("0a0a0a0a-0000-4000-8000-00000000000a");
    private static final UUID TENANT_B = UUID.fromString("0b0b0b0b-0000-4000-8000-00000000000b");
    private static final UUID USER_IN_A = UUID.fromString("1a1a1a1a-0000-4000-8000-00000000001a");
    private static final UUID USER_IN_B = UUID.fromString("1b1b1b1b-0000-4000-8000-00000000001b");

    private UserRepository userRepository;
    private RbacPermissionEvaluator evaluator;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        userRepository = mock(UserRepository.class);
        TenantFilterBypass bypass = mock(TenantFilterBypass.class);
        when(bypass.runWithoutTenantFilter(any())).thenAnswer(inv -> ((Supplier<Object>) inv.getArgument(0)).get());
        RbacAuthorizationService rbac = new RbacAuthorizationService(userRepository, mock(RoleRepository.class), bypass);
        evaluator = new RbacPermissionEvaluator(rbac);

        when(userRepository.findById(USER_IN_A)).thenReturn(Optional.of(user(USER_IN_A, "a@example.test",
                UserType.TENANT_MEMBER, TENANT_A)));
        when(userRepository.findById(USER_IN_B)).thenReturn(Optional.of(user(USER_IN_B, "b@example.test",
                UserType.TENANT_MEMBER, TENANT_B)));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static User user(UUID id, String email, UserType type, UUID tenantId) {
        return User.builder()
                .id(id)
                .email(email)
                .userType(type)
                .tenant(tenantId == null ? null : Tenant.builder().id(tenantId).name("t").build())
                .build();
    }

    private Authentication signedInAs(String email, UserType type, UUID tenantId) {
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user(UUID.randomUUID(), email, type, tenantId)));
        Authentication auth = new UsernamePasswordAuthenticationToken(email, "n/a", List.of());
        SecurityContextHolder.getContext().setAuthentication(auth);
        return auth;
    }

    @Test
    void hasPermission_WhenUserTargetInAnotherTenant_ShouldDeny() {
        Authentication admin = signedInAs("admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);

        assertThat(evaluator.hasPermission(admin, USER_IN_B, "User", "enrollment:read")).isFalse();
    }

    @Test
    void hasPermission_WhenUserTargetInSameTenant_ShouldGrant() {
        Authentication admin = signedInAs("admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);

        assertThat(evaluator.hasPermission(admin, USER_IN_A, "User", "enrollment:read")).isTrue();
    }

    @Test
    void hasPermission_WhenUserTargetIdIsAString_ShouldStillBeScoped() {
        Authentication admin = signedInAs("admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);

        assertThat(evaluator.hasPermission(admin, USER_IN_B.toString(), "user_settings", "read")).isFalse();
        assertThat(evaluator.hasPermission(admin, USER_IN_A.toString(), "user_settings", "read")).isTrue();
    }

    @Test
    void hasPermission_WhenUserTargetUnknownOrMalformed_ShouldDeny() {
        Authentication admin = signedInAs("admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);

        assertThat(evaluator.hasPermission(admin, UUID.randomUUID(), "User", "enrollment:read")).isFalse();
        assertThat(evaluator.hasPermission(admin, "not-a-uuid", "User", "enrollment:read")).isFalse();
    }

    @Test
    void hasPermission_WhenTenantTargetIsAnotherTenant_ShouldDeny() {
        Authentication admin = signedInAs("admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);

        assertThat(evaluator.hasPermission(admin, TENANT_B, "Tenant", "auth_method:read")).isFalse();
        assertThat(evaluator.hasPermission(admin, TENANT_A, "Tenant", "auth_method:read")).isTrue();
    }

    @Test
    void hasPermission_WhenTargetTypeHasNoScopeRule_ShouldDenyATargetedCheck() {
        Authentication admin = signedInAs("admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);

        assertThat(evaluator.hasPermission(admin, UUID.randomUUID(), "Device", "read")).isFalse();
    }

    @Test
    void hasPermission_WhenTargetIdIsNull_ShouldCheckThePermissionOnly() {
        Authentication admin = signedInAs("admin-a@example.test", UserType.TENANT_ADMIN, TENANT_A);

        assertThat(evaluator.hasPermission(admin, null, "Device", "device:register")).isTrue();
    }

    @Test
    void hasPermission_WhenRoot_ShouldGrantATargetInAnyTenant() {
        Authentication root = signedInAs("root@example.test", UserType.ROOT, null);

        assertThat(evaluator.hasPermission(root, USER_IN_B, "User", "enrollment:create")).isTrue();
        assertThat(evaluator.hasPermission(root, TENANT_B, "Tenant", "auth_method:configure")).isTrue();
    }

    @Test
    void hasPermission_WhenMemberLacksThePermission_ShouldDenyEvenInOwnTenant() {
        Authentication member = signedInAs("member-a@example.test", UserType.TENANT_MEMBER, TENANT_A);

        assertThat(evaluator.hasPermission(member, USER_IN_A, "User", "enrollment:read")).isFalse();
    }
}
