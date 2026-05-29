package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.TenantEmailDomainResponse;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.TenantEmailDomainConflictException;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantEmailDomain;
import com.fivucsas.identity.entity.TenantEmailDomainId;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.TenantEmailDomainRepository;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ManageTenantEmailDomainService Tests")
class ManageTenantEmailDomainServiceTest {

    private static final UUID TENANT_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");

    @Mock
    private TenantEmailDomainRepository emailDomainRepository;
    @Mock
    private JpaTenantRepository tenantRepository;
    @Mock
    private AuditLogPort auditLogPort;

    @InjectMocks
    private ManageTenantEmailDomainService service;

    private Tenant tenant(boolean enforce) {
        return Tenant.builder()
                .id(TENANT_ID)
                .name("Marmara University")
                .slug("marmara")
                .contactEmail("admin@marmara.edu.tr")
                .enforceDomainMatching(enforce)
                .build();
    }

    @BeforeEach
    void setUp() {
        lenient().when(tenantRepository.findById(TENANT_ID)).thenReturn(Optional.of(tenant(false)));
    }

    @Test
    @DisplayName("addDomain normalises, validates, and persists a new domain")
    void addDomainHappyPath() {
        when(emailDomainRepository.findByIdEmailDomainIgnoreCase("marmara.edu.tr"))
                .thenReturn(Optional.empty());
        when(emailDomainRepository.findById(TenantEmailDomainId.of(TENANT_ID, "marmara.edu.tr")))
                .thenReturn(Optional.empty());
        when(emailDomainRepository.saveAndFlush(any(TenantEmailDomain.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        TenantEmailDomainResponse resp = service.addDomain(TENANT_ID, "  MARMARA.edu.tr ", false);

        assertThat(resp.getDomain()).isEqualTo("marmara.edu.tr");
        assertThat(resp.isPrimary()).isFalse();
        verify(auditLogPort).logSecurityEvent(eq(TENANT_ID.toString()), eq("TENANT_EMAIL_DOMAIN_ADDED"), any(), any());
    }

    @Test
    @DisplayName("addDomain rejects '@' and malformed domains with IllegalArgumentException")
    void addDomainRejectsMalformed() {
        assertThatThrownBy(() -> service.addDomain(TENANT_ID, "user@marmara.edu.tr", false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.addDomain(TENANT_ID, "not a domain", false))
                .isInstanceOf(IllegalArgumentException.class);
        verify(emailDomainRepository, never()).saveAndFlush(any());
    }

    @Test
    @DisplayName("addDomain returns 409-conflict when domain is claimed by another tenant")
    void addDomainConflictWhenClaimedByAnother() {
        UUID otherTenant = UUID.randomUUID();
        when(emailDomainRepository.findByIdEmailDomainIgnoreCase("marun.edu.tr"))
                .thenReturn(Optional.of(TenantEmailDomain.create(otherTenant, "marun.edu.tr", false)));

        assertThatThrownBy(() -> service.addDomain(TENANT_ID, "marun.edu.tr", false))
                .isInstanceOf(TenantEmailDomainConflictException.class)
                .satisfies(ex -> assertThat(((TenantEmailDomainConflictException) ex).getErrorCode())
                        .isEqualTo(TenantEmailDomainConflictException.ALREADY_CLAIMED));
        verify(emailDomainRepository, never()).saveAndFlush(any());
    }

    @Test
    @DisplayName("removeDomain refuses the last domain when enforcement is on")
    void removeLastDomainRefusedUnderEnforcement() {
        when(tenantRepository.findById(TENANT_ID)).thenReturn(Optional.of(tenant(true)));
        TenantEmailDomain only = TenantEmailDomain.create(TENANT_ID, "marmara.edu.tr", true);
        when(emailDomainRepository.findById(TenantEmailDomainId.of(TENANT_ID, "marmara.edu.tr")))
                .thenReturn(Optional.of(only));
        when(emailDomainRepository.findByIdTenantId(TENANT_ID)).thenReturn(List.of(only));

        assertThatThrownBy(() -> service.removeDomain(TENANT_ID, "marmara.edu.tr"))
                .isInstanceOf(TenantEmailDomainConflictException.class)
                .satisfies(ex -> assertThat(((TenantEmailDomainConflictException) ex).getErrorCode())
                        .isEqualTo(TenantEmailDomainConflictException.LAST_DOMAIN));
        verify(emailDomainRepository, never()).delete(any());
    }

    @Test
    @DisplayName("removeDomain allows removing the last domain when enforcement is OFF")
    void removeLastDomainAllowedWhenNotEnforced() {
        TenantEmailDomain only = TenantEmailDomain.create(TENANT_ID, "marmara.edu.tr", true);
        when(emailDomainRepository.findById(TenantEmailDomainId.of(TENANT_ID, "marmara.edu.tr")))
                .thenReturn(Optional.of(only));
        when(emailDomainRepository.findByIdTenantId(TENANT_ID)).thenReturn(List.of(only));

        service.removeDomain(TENANT_ID, "marmara.edu.tr");

        verify(emailDomainRepository).delete(only);
        verify(auditLogPort).logSecurityEvent(eq(TENANT_ID.toString()), eq("TENANT_EMAIL_DOMAIN_REMOVED"), any(), any());
    }

    @Test
    @DisplayName("setPrimaryDomain dethrones the previous primary then promotes the target")
    void setPrimaryDethronesPrevious() {
        TenantEmailDomain oldPrimary = TenantEmailDomain.create(TENANT_ID, "marmara.edu.tr", true);
        TenantEmailDomain target = TenantEmailDomain.create(TENANT_ID, "marun.edu.tr", false);
        when(emailDomainRepository.findById(TenantEmailDomainId.of(TENANT_ID, "marun.edu.tr")))
                .thenReturn(Optional.of(target));
        when(emailDomainRepository.findByIdTenantId(TENANT_ID)).thenReturn(List.of(oldPrimary, target));
        when(emailDomainRepository.saveAndFlush(any(TenantEmailDomain.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        TenantEmailDomainResponse resp = service.setPrimaryDomain(TENANT_ID, "marun.edu.tr");

        assertThat(resp.getDomain()).isEqualTo("marun.edu.tr");
        assertThat(resp.isPrimary()).isTrue();
        assertThat(oldPrimary.isPrimary()).isFalse(); // dethroned
        assertThat(target.isPrimary()).isTrue();
        verify(auditLogPort).logSecurityEvent(eq(TENANT_ID.toString()), eq("TENANT_EMAIL_DOMAIN_PRIMARY_SET"), any(), any());
    }
}
