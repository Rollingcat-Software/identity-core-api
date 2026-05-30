package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.UpdateTenantCommand;
import com.fivucsas.identity.application.dto.response.TenantResponse;
import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.model.tenant.TenantConfiguration;
import com.fivucsas.identity.domain.model.tenant.TenantStatus;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * S1 (cross-tenant write / IDOR) regression tests for
 * {@link ManageTenantService#updateTenant}.
 *
 * <p>Before the fix, {@code PUT /api/v1/tenants/{tenantId}} only required the
 * {@code tenant:configure} permission. A {@code TENANT_ADMIN} of tenant A could
 * therefore overwrite tenant B's configuration by passing B's id. The service
 * now consults {@link TenantScopeResolver#canAccessTenant(UUID)} before
 * applying any change. {@code canAccessTenant} returns {@code true} for
 * ROOT (null scope), so root keeps cross-tenant access while
 * everyone else is confined to their own tenant. An out-of-scope caller is
 * rejected with {@link AccessDeniedException} (→ HTTP 403 via
 * {@code GlobalExceptionHandler}).</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ManageTenantService — tenant-scope guard on update (S1)")
class ManageTenantServiceUpdateScopeTest {

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private com.fivucsas.identity.repository.TenantEmailDomainRepository tenantEmailDomainRepository;

    @Mock
    private com.fivucsas.identity.application.port.output.AuditLogPort auditLogPort;

    @Mock
    private TenantScopeResolver tenantScopeResolver;

    @Mock
    private com.fivucsas.identity.security.RbacAuthorizationService rbacService;

    @InjectMocks
    private ManageTenantService service;

    private UUID tenantId;
    private Tenant existingTenant;

    @BeforeEach
    void setUp() {
        // P1-4 added rbacService to ManageTenantService (audit actor resolution via
        // currentActorId()). Stub it leniently — the out-of-scope test throws before
        // the audit path, so not every test reaches this call.
        org.mockito.Mockito.lenient().when(rbacService.getCurrentUserId())
                .thenReturn(java.util.Optional.empty());
        tenantId = UUID.randomUUID();
        Instant now = Instant.now();
        existingTenant = Tenant.reconstitute(
            tenantId,
            "Acme Corp",
            "acme",
            "desc",
            "ops@acme.test",
            "+10000000000",
            TenantStatus.ACTIVE,
            TenantConfiguration.defaultConfiguration(),
            now,
            now
        );
    }

    @Test
    @DisplayName("TENANT_ADMIN of tenant A updating tenant B is rejected and nothing is persisted")
    void updateTenant_outOfScope_throwsAccessDeniedAndDoesNotPersist() {
        // Caller (e.g. TENANT_ADMIN of a different tenant) is NOT in scope for
        // this tenant id.
        when(tenantScopeResolver.canAccessTenant(tenantId)).thenReturn(false);

        UpdateTenantCommand command = UpdateTenantCommand.builder()
            .tenantId(tenantId.toString())
            .name("Hijacked Name")
            .build();

        assertThatThrownBy(() -> service.updateTenant(command))
            .isInstanceOf(AccessDeniedException.class);

        // The guard runs before the load + write: no read, no save, no audit.
        verify(tenantRepository, never()).findById(any(UUID.class));
        verify(tenantRepository, never()).save(any(Tenant.class));
    }

    @Test
    @DisplayName("Same-tenant (in-scope) caller may update their own tenant")
    void updateTenant_inScope_appliesUpdate() {
        when(tenantScopeResolver.canAccessTenant(tenantId)).thenReturn(true);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(existingTenant));
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> inv.getArgument(0));
        when(userRepository.countByTenantId(any(UUID.class))).thenReturn(3L);

        UpdateTenantCommand command = UpdateTenantCommand.builder()
            .tenantId(tenantId.toString())
            .name("Renamed Corp")
            .build();

        TenantResponse response = service.updateTenant(command);

        assertThat(response).isNotNull();
        assertThat(response.getName()).isEqualTo("Renamed Corp");
        verify(tenantRepository).save(any(Tenant.class));
    }

    @Test
    @DisplayName("Root/ROOT (null scope ⇒ canAccessTenant true) retains cross-tenant update")
    void updateTenant_rootCrossTenant_appliesUpdate() {
        // Root has no scope restriction, so canAccessTenant() returns true even
        // for a tenant the caller is not a member of.
        when(tenantScopeResolver.canAccessTenant(tenantId)).thenReturn(true);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(existingTenant));
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> inv.getArgument(0));
        when(userRepository.countByTenantId(any(UUID.class))).thenReturn(0L);

        UpdateTenantCommand command = UpdateTenantCommand.builder()
            .tenantId(tenantId.toString())
            .name("Admin Rename")
            .build();

        TenantResponse response = service.updateTenant(command);

        assertThat(response).isNotNull();
        assertThat(response.getName()).isEqualTo("Admin Rename");
        verify(tenantRepository).save(any(Tenant.class));
    }
}
