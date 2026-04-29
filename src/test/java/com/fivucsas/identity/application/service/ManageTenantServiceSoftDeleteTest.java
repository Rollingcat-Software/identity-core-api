package com.fivucsas.identity.application.service;

import com.fivucsas.identity.domain.exception.TenantNotFoundException;
import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.model.tenant.TenantConfiguration;
import com.fivucsas.identity.domain.model.tenant.TenantStatus;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * EDGE-P1 #5 (AUDIT_2026-04-28) — Tenant soft-delete tests.
 *
 * <p>Verifies that:
 * <ul>
 *   <li>{@code softDeleteTenant} routes through {@code TenantRepository.deleteById},
 *       which on the JPA side is rewritten by Hibernate's {@code @SQLDelete}
 *       to {@code UPDATE tenants SET deleted_at = NOW()}.</li>
 *   <li>{@code deleteTenant(String)} (existing API) is now a wrapper that
 *       routes through the soft path — no behavioural change for callers.</li>
 *   <li>Both throw {@link TenantNotFoundException} for missing/already
 *       soft-deleted rows (the {@code @SQLRestriction} hides them from
 *       {@code findById}).</li>
 * </ul>
 *
 * <p>The actual Hibernate SQL rewrite is exercised by integration tests with
 * a real DB (we cannot meaningfully assert Hibernate behaviour with mocks);
 * here we verify that the service layer NEVER calls a hard-delete path.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ManageTenantService — soft delete contract")
class ManageTenantServiceSoftDeleteTest {

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private ManageTenantService service;

    private UUID tenantId;
    private Tenant existingTenant;

    @BeforeEach
    void setUp() {
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
    void softDeleteTenant_existingTenant_callsRepositoryDeleteById() {
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(existingTenant));

        service.softDeleteTenant(tenantId);

        // The repository deleteById call is the bridge to Hibernate's @SQLDelete,
        // which rewrites to UPDATE tenants SET deleted_at = NOW().
        // We verify the contract at this layer; SQL rewrite is integration-tested.
        verify(tenantRepository).findById(tenantId);
        verify(tenantRepository).deleteById(tenantId);
        verifyNoMoreInteractions(tenantRepository);
    }

    @Test
    void softDeleteTenant_nonExistentTenant_throwsAndDoesNotCallDelete() {
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.softDeleteTenant(tenantId))
            .isInstanceOf(TenantNotFoundException.class);

        verify(tenantRepository).findById(tenantId);
        verify(tenantRepository, never()).deleteById(any(UUID.class));
    }

    @Test
    void deleteTenant_stringApi_routesThroughSoftDelete() {
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(existingTenant));

        service.deleteTenant(tenantId.toString());

        // Same code path as softDeleteTenant — repository.deleteById is the
        // single chokepoint, rewritten by @SQLDelete.
        verify(tenantRepository).findById(tenantId);
        verify(tenantRepository).deleteById(tenantId);
        verifyNoMoreInteractions(tenantRepository);
    }

    @Test
    void deleteTenant_nonExistent_throwsTenantNotFound() {
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.deleteTenant(tenantId.toString()))
            .isInstanceOf(TenantNotFoundException.class);

        verify(tenantRepository, never()).deleteById(any(UUID.class));
    }
}
