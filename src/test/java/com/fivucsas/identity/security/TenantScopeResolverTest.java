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

    /** Binds a mock HTTP request carrying the given X-Active-Tenant alias header value. */
    private void bindRequestWithActiveTenant(String headerValue) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (headerValue != null) {
            request.addHeader(TenantScopeResolver.ACTIVE_TENANT_HEADER, headerValue);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    /** Binds a mock HTTP request carrying the canonical X-Tenant-ID header value. */
    private void bindRequestWithTenantId(String headerValue) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (headerValue != null) {
            request.addHeader(TenantScopeResolver.TENANT_ID_HEADER, headerValue);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    /** Binds a request carrying BOTH headers (to assert canonical precedence). */
    private void bindRequestWithBothHeaders(String tenantIdValue, String activeTenantValue) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (tenantIdValue != null) {
            request.addHeader(TenantScopeResolver.TENANT_ID_HEADER, tenantIdValue);
        }
        if (activeTenantValue != null) {
            request.addHeader(TenantScopeResolver.ACTIVE_TENANT_HEADER, activeTenantValue);
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

    // ===== Unified switcher: canonical X-Tenant-ID header =====

    @Test
    @DisplayName("ROOT + valid X-Tenant-ID → scope narrows to the selected tenant")
    void rootWithCanonicalHeaderScopesToSelectedTenant() {
        UUID selected = UUID.randomUUID();
        when(rbacService.isSuperAdmin()).thenReturn(true);
        when(tenantRepository.existsById(selected)).thenReturn(true);
        bindRequestWithTenantId(selected.toString());

        assertThat(resolver.currentScope()).isEqualTo(selected);
        assertThat(resolver.isUnrestricted()).isFalse();
        assertThat(resolver.canAccessTenant(selected)).isTrue();
    }

    @Test
    @DisplayName("ROOT + both headers present → canonical X-Tenant-ID wins over X-Active-Tenant")
    void canonicalHeaderTakesPrecedenceOverAlias() {
        UUID canonical = UUID.randomUUID();
        UUID alias = UUID.randomUUID();
        when(rbacService.isSuperAdmin()).thenReturn(true);
        when(tenantRepository.existsById(canonical)).thenReturn(true);
        bindRequestWithBothHeaders(canonical.toString(), alias.toString());

        assertThat(resolver.currentScope()).isEqualTo(canonical);
        assertThat(resolver.currentScope()).isNotEqualTo(alias);
    }

    @Test
    @DisplayName("ROOT + blank X-Tenant-ID but valid X-Active-Tenant → alias fallback honoured")
    void aliasHonouredWhenCanonicalBlank() {
        UUID alias = UUID.randomUUID();
        when(rbacService.isSuperAdmin()).thenReturn(true);
        when(tenantRepository.existsById(alias)).thenReturn(true);
        bindRequestWithBothHeaders("", alias.toString());

        assertThat(resolver.currentScope()).isEqualTo(alias);
    }

    @Test
    @DisplayName("SECURITY: TENANT_ADMIN + canonical X-Tenant-ID for a foreign tenant → IGNORED, home tenant returned")
    void tenantAdminCannotEscalateViaCanonicalHeader() {
        UUID foreignTenant = UUID.randomUUID();
        when(rbacService.isSuperAdmin()).thenReturn(false);
        when(rbacService.getCurrentUser()).thenReturn(Optional.of(tenantUser));
        lenient().when(tenantRepository.existsById(foreignTenant)).thenReturn(true);
        bindRequestWithTenantId(foreignTenant.toString());

        assertThat(resolver.currentScope()).isEqualTo(tenantId);
        assertThat(resolver.currentScope()).isNotEqualTo(foreignTenant);
        assertThat(resolver.canAccessTenant(foreignTenant)).isFalse();
    }

    @Test
    @DisplayName("ROOT + no header → cross-tenant (null) default preserved")
    void rootNoHeaderStaysCrossTenant() {
        when(rbacService.isSuperAdmin()).thenReturn(true);
        bindRequestWithTenantId(null);

        assertThat(resolver.currentScope()).isNull();
        assertThat(resolver.isUnrestricted()).isTrue();
    }

    // ===== isCrossTenantAdmin (capability, independent of active selection) =====

    @Test
    @DisplayName("isCrossTenantAdmin → true for SUPER_ADMIN even AFTER selecting a tenant")
    void crossTenantAdminCapabilitySurvivesSelection() {
        UUID selected = UUID.randomUUID();
        when(rbacService.isSuperAdmin()).thenReturn(true);
        lenient().when(tenantRepository.existsById(selected)).thenReturn(true);
        bindRequestWithTenantId(selected.toString());

        // Selected a tenant → not "unrestricted" anymore...
        assertThat(resolver.currentScope()).isEqualTo(selected);
        assertThat(resolver.isUnrestricted()).isFalse();
        // ...but the cross-tenant capability (drives the switcher dropdown) holds.
        assertThat(resolver.isCrossTenantAdmin()).isTrue();
    }

    @Test
    @DisplayName("isCrossTenantAdmin → false for a TENANT_ADMIN")
    void tenantAdminIsNotCrossTenantAdmin() {
        when(rbacService.isSuperAdmin()).thenReturn(false);

        assertThat(resolver.isCrossTenantAdmin()).isFalse();
    }
}
