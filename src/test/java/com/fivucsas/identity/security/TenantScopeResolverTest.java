package com.fivucsas.identity.security;

import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.JpaTenantRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
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

    @Mock
    private JpaTenantRepository tenantRepository;

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

    @AfterEach
    void clearRequestContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    /** Binds a mock HTTP request carrying the given X-Active-Tenant header value. */
    private void bindRequestWithActiveTenant(String headerValue) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (headerValue != null) {
            request.addHeader(TenantScopeResolver.ACTIVE_TENANT_HEADER, headerValue);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
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

    // ===== Tenant switcher: X-Active-Tenant header =====

    @Test
    @DisplayName("ROOT + valid X-Active-Tenant → scope narrows to the selected tenant")
    void rootWithHeaderScopesToSelectedTenant() {
        UUID selected = UUID.randomUUID();
        when(rbacService.isSuperAdmin()).thenReturn(true);
        when(tenantRepository.existsById(selected)).thenReturn(true);
        bindRequestWithActiveTenant(selected.toString());

        assertThat(resolver.currentScope()).isEqualTo(selected);
        assertThat(resolver.isUnrestricted()).isFalse();
        assertThat(resolver.canAccessTenant(selected)).isTrue();
    }

    @Test
    @DisplayName("ROOT + no X-Active-Tenant header → unrestricted (cross-tenant)")
    void rootWithoutHeaderStaysUnrestricted() {
        when(rbacService.isSuperAdmin()).thenReturn(true);
        bindRequestWithActiveTenant(null);

        assertThat(resolver.currentScope()).isNull();
        assertThat(resolver.isUnrestricted()).isTrue();
    }

    @Test
    @DisplayName("ROOT + X-Active-Tenant for an unknown tenant → ignored, stays cross-tenant")
    void rootWithUnknownTenantHeaderIgnored() {
        UUID unknown = UUID.randomUUID();
        when(rbacService.isSuperAdmin()).thenReturn(true);
        when(tenantRepository.existsById(unknown)).thenReturn(false);
        bindRequestWithActiveTenant(unknown.toString());

        assertThat(resolver.currentScope()).isNull();
    }

    @Test
    @DisplayName("ROOT + malformed X-Active-Tenant value → ignored, stays cross-tenant")
    void rootWithMalformedHeaderIgnored() {
        when(rbacService.isSuperAdmin()).thenReturn(true);
        bindRequestWithActiveTenant("not-a-uuid");

        assertThat(resolver.currentScope()).isNull();
    }

    @Test
    @DisplayName("SECURITY: TENANT_ADMIN + X-Active-Tenant for a foreign tenant → header IGNORED, home tenant returned")
    void tenantAdminCannotEscalateViaHeader() {
        UUID foreignTenant = UUID.randomUUID();
        when(rbacService.isSuperAdmin()).thenReturn(false);
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(tenantUser));
        // Even a perfectly valid, existing foreign tenant id must not be honoured.
        lenient().when(tenantRepository.existsById(foreignTenant)).thenReturn(true);
        bindRequestWithActiveTenant(foreignTenant.toString());

        assertThat(resolver.currentScope()).isEqualTo(tenantId);
        assertThat(resolver.currentScope()).isNotEqualTo(foreignTenant);
        assertThat(resolver.canAccessTenant(foreignTenant)).isFalse();
    }

    @Test
    @DisplayName("SECURITY: tenantless USER + X-Active-Tenant header → still fail-closed, never the foreign tenant")
    void tenantlessUserCannotEscalateViaHeader() {
        UUID foreignTenant = UUID.randomUUID();
        when(rbacService.isSuperAdmin()).thenReturn(false);
        User tenantless = User.builder().id(UUID.randomUUID()).tenant(null).build();
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(tenantless));
        bindRequestWithActiveTenant(foreignTenant.toString());

        assertThat(resolver.currentScope()).isEqualTo(TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE);
    }
}
