package com.fivucsas.identity.security;

import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantScopeResolver} — the shared helper that maps a
 * caller to the tenant scope they may enumerate.
 *
 * <p>Mirrors the v2 pattern introduced for {@code ManageUserService} in PR #23
 * so behaviour is identical across controllers/services.</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TenantScopeResolver")
class TenantScopeResolverTest {

    @Mock
    private RbacAuthorizationService rbacService;

    @InjectMocks
    private TenantScopeResolver resolver;

    private UUID tenantId;
    private User tenantUser;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        Tenant tenant = Tenant.builder().id(tenantId).build();
        tenantUser = User.builder().id(UUID.randomUUID()).tenant(tenant).build();
    }

    @Test
    @DisplayName("SUPER_ADMIN → null scope (unrestricted)")
    void superAdminGetsNullScope() {
        when(rbacService.isSuperAdmin()).thenReturn(true);

        assertThat(resolver.currentScope()).isNull();
        assertThat(resolver.isUnrestricted()).isTrue();
        assertThat(resolver.canAccessTenant(UUID.randomUUID())).isTrue();
    }

    @Test
    @DisplayName("TENANT_ADMIN with a tenant → their own tenant UUID")
    void tenantAdminGetsOwnTenantScope() {
        when(rbacService.isSuperAdmin()).thenReturn(false);
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(tenantUser));

        assertThat(resolver.currentScope()).isEqualTo(tenantId);
        assertThat(resolver.isUnrestricted()).isFalse();
        assertThat(resolver.canAccessTenant(tenantId)).isTrue();
        assertThat(resolver.canAccessTenant(UUID.randomUUID())).isFalse();
    }

    @Test
    @DisplayName("Caller resolves but has no tenant → fail-closed sentinel")
    void userWithoutTenantGetsFailClosed() {
        when(rbacService.isSuperAdmin()).thenReturn(false);
        User tenantless = User.builder().id(UUID.randomUUID()).tenant(null).build();
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(tenantless));

        assertThat(resolver.currentScope()).isEqualTo(TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE);
        assertThat(resolver.isUnrestricted()).isFalse();
    }

    @Test
    @DisplayName("Unresolvable caller → fail-closed sentinel")
    void unresolvedCallerGetsFailClosed() {
        when(rbacService.isSuperAdmin()).thenReturn(false);
        when(rbacService.getCurrentUser()).thenReturn(Optional.empty());

        assertThat(resolver.currentScope()).isEqualTo(TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE);
    }

    @Test
    @DisplayName("canAccessTenant(null) → false, regardless of caller")
    void canAccessTenantRejectsNullArgument() {
        // Don't stub rbacService — assertion short-circuits on null argument
        // before the scope is resolved.
        assertThat(resolver.canAccessTenant(null)).isFalse();
    }

    @Test
    @DisplayName("Fail-closed sentinel never equals a real tenant UUID")
    void failClosedSentinelIsDistinct() {
        assertThat(TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE)
                .isEqualTo(new UUID(0L, 0L))
                .isNotEqualTo(UUID.randomUUID());
    }
}
