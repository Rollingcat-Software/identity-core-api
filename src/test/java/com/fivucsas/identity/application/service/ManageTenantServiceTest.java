package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateTenantCommand;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.repository.TenantEmailDomainRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Focused tests for {@link ManageTenantService} audit attribution (P1-4).
 *
 * <p>Pins that lifecycle events route through
 * {@link AuditLogPort#logTenantManagementEvent} with the acting admin as actor
 * and the managed tenant as resource — NOT the legacy {@code logSecurityEvent}
 * where the single id slot conflated actor and resource.</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ManageTenantService — audit attribution [P1-4]")
class ManageTenantServiceTest {

    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private TenantEmailDomainRepository tenantEmailDomainRepository;
    @Mock
    private AuditLogPort auditLogPort;
    @Mock
    private TenantScopeResolver tenantScopeResolver;
    @Mock
    private RbacAuthorizationService rbacService;

    @InjectMocks
    private ManageTenantService service;

    /** Reconstitutes the given tenant with a freshly-assigned id (mimics persistence). */
    private static Tenant withId(Tenant t) {
        return Tenant.reconstitute(UUID.randomUUID(), t.getName(), t.getSlug(),
                t.getDescription(), t.getContactEmail(), t.getContactPhone(),
                t.getStatus(), t.getConfiguration(), t.getCreatedAt(), t.getUpdatedAt());
    }

    private CreateTenantCommand createCommand() {
        return CreateTenantCommand.builder()
                .name("Acme University")
                .slug("acme")
                .description("test tenant")
                .contactEmail("admin@acme.edu")
                .contactPhone("+15551234567")
                .build();
    }

    @Test
    @DisplayName("createTenant attributes the acting admin (actor) and the new tenant (resource)")
    void createTenantAttributesActorAndResource() {
        UUID actorId = UUID.randomUUID();
        when(rbacService.getCurrentUserId()).thenReturn(Optional.of(actorId));
        when(tenantRepository.existsByName(any())).thenReturn(false);
        when(tenantRepository.existsBySlug(any())).thenReturn(false);
        // The persistence adapter assigns the id on save; mimic that so the
        // audit emission (which reads tenant.getId()) has a real resource id.
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> withId(inv.getArgument(0)));
        lenient().when(userRepository.countByTenantId(any())).thenReturn(0L);

        service.createTenant(createCommand());

        verify(auditLogPort).logTenantManagementEvent(
                eq(actorId.toString()),
                eq("TENANT_CREATED"),
                any(),   // the freshly-minted tenant id (resource)
                any());
    }

    @Test
    @DisplayName("createTenant with NO authenticated admin (self-service onboarding) → actor is null")
    void createTenantSelfServiceHasNullActor() {
        when(rbacService.getCurrentUserId()).thenReturn(Optional.empty());
        when(tenantRepository.existsByName(any())).thenReturn(false);
        when(tenantRepository.existsBySlug(any())).thenReturn(false);
        // The persistence adapter assigns the id on save; mimic that so the
        // audit emission (which reads tenant.getId()) has a real resource id.
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(inv -> withId(inv.getArgument(0)));
        lenient().when(userRepository.countByTenantId(any())).thenReturn(0L);

        service.createTenant(createCommand());

        verify(auditLogPort).logTenantManagementEvent(
                isNull(),
                eq("TENANT_CREATED"),
                any(),
                any());
    }
}
