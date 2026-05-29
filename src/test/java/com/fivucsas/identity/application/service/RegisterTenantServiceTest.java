package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterTenantCommand;
import com.fivucsas.identity.application.dto.response.TenantOnboardingResponse;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TenantProvisioningPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.DuplicateTenantException;
import com.fivucsas.identity.domain.exception.PersonalEmailNotAllowedException;
import com.fivucsas.identity.domain.exception.TenantEmailDomainConflictException;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.TenantEmailDomain;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.repository.TenantEmailDomainRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RegisterTenantService — self-service onboarding")
class RegisterTenantServiceTest {

    private static final String DEFAULT_BLOCKLIST =
            "gmail.com,outlook.com,hotmail.com,yahoo.com,mailinator.com,gmx.,yandex.";

    @Mock private TenantRepository tenantRepository;
    @Mock private UserRepository userRepository;
    @Mock private TenantEmailDomainRepository tenantEmailDomainRepository;
    @Mock private PasswordEncoderPort passwordEncoder;
    @Mock private TenantProvisioningPort tenantProvisioningPort;
    @Mock private EmailService emailService;
    @Mock private AuditLogPort auditLogPort;

    @InjectMocks private RegisterTenantService service;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "requireAdminApproval", false);
        ReflectionTestUtils.setField(service, "onboardingEnabled", true);
        ReflectionTestUtils.setField(service, "blockedEmailDomainsCsv", DEFAULT_BLOCKLIST);
    }

    private RegisterTenantCommand validCommand() {
        return RegisterTenantCommand.builder()
                .orgName("Acme Corp")
                .adminEmail("admin@acme.example")
                .adminPassword("Sup3rSecret!")
                .adminFirstName("Ada")
                .adminLastName("Lovelace")
                .ipAddress("203.0.113.7")
                .userAgent("JUnit")
                .build();
    }

    private TenantProvisioningPort.Result stubProvision() {
        TenantProvisioningPort.Result result = new TenantProvisioningPort.Result(
                UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), "verify-token-123");
        when(tenantProvisioningPort.provision(any())).thenReturn(result);
        return result;
    }

    @Test
    @DisplayName("happy path — creates TRIAL tenant, derives slug + domain, sends verification email")
    void happyPath() {
        when(tenantRepository.existsByName("Acme Corp")).thenReturn(false);
        when(userRepository.existsByEmail("admin@acme.example")).thenReturn(false);
        when(tenantRepository.existsBySlug("acme-corp")).thenReturn(false);
        when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCase("acme.example"))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode("Sup3rSecret!")).thenReturn("$2a$12$hashed");
        TenantProvisioningPort.Result result = stubProvision();

        TenantOnboardingResponse response = service.register(validCommand());

        // Slug derived from org name; domain derived from admin email
        ArgumentCaptor<TenantProvisioningPort.Params> params =
                ArgumentCaptor.forClass(TenantProvisioningPort.Params.class);
        verify(tenantProvisioningPort).provision(params.capture());
        assertThat(params.getValue().slug()).isEqualTo("acme-corp");
        assertThat(params.getValue().emailDomain()).isEqualTo("acme.example");
        assertThat(params.getValue().hashedPassword()).isEqualTo("$2a$12$hashed");
        // Default policy (no admin approval) → TRIAL
        assertThat(params.getValue().initialStatus()).isEqualTo("TRIAL");

        assertThat(response.getStatus()).isEqualTo("TRIAL");
        assertThat(response.isRequiresAdminApproval()).isFalse();
        assertThat(response.getSlug()).isEqualTo("acme-corp");
        assertThat(response.getEmailDomain()).isEqualTo("acme.example");
        assertThat(response.getTenantId()).isEqualTo(result.tenantId().toString());

        verify(emailService).sendTenantOnboardingVerification(
                eq("admin@acme.example"), eq("Ada"), eq("Acme Corp"), eq("verify-token-123"));
        verify(auditLogPort).logSecurityEvent(
                eq(result.tenantId().toString()), eq("TENANT_SELF_ONBOARDED"), anyString(), anyString());
    }

    @Test
    @DisplayName("require-admin-approval=true → tenant starts PENDING")
    void pendingWhenApprovalRequired() {
        ReflectionTestUtils.setField(service, "requireAdminApproval", true);
        when(tenantRepository.existsByName(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);
        when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCase(anyString()))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$12$hashed");
        stubProvision();

        TenantOnboardingResponse response = service.register(validCommand());

        assertThat(response.getStatus()).isEqualTo("PENDING");
        assertThat(response.isRequiresAdminApproval()).isTrue();
        ArgumentCaptor<TenantProvisioningPort.Params> params =
                ArgumentCaptor.forClass(TenantProvisioningPort.Params.class);
        verify(tenantProvisioningPort).provision(params.capture());
        assertThat(params.getValue().initialStatus()).isEqualTo("PENDING");
    }

    @Test
    @DisplayName("duplicate org name → DuplicateTenantException (409), no provisioning")
    void duplicateName() {
        when(tenantRepository.existsByName("Acme Corp")).thenReturn(true);

        assertThatThrownBy(() -> service.register(validCommand()))
                .isInstanceOf(DuplicateTenantException.class);
        verifyNoInteractions(tenantProvisioningPort, emailService);
    }

    @Test
    @DisplayName("explicit slug already taken → DuplicateTenantException (409)")
    void duplicateExplicitSlug() {
        RegisterTenantCommand cmd = RegisterTenantCommand.builder()
                .orgName("Acme Corp").slug("taken")
                .adminEmail("admin@acme.example").adminPassword("Sup3rSecret!")
                .adminFirstName("Ada").adminLastName("Lovelace").build();
        when(tenantRepository.existsByName("Acme Corp")).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(tenantRepository.existsBySlug("taken")).thenReturn(true);

        assertThatThrownBy(() -> service.register(cmd))
                .isInstanceOf(DuplicateTenantException.class);
        verifyNoInteractions(tenantProvisioningPort);
    }

    @Test
    @DisplayName("derived slug collision → appends numeric suffix")
    void slugCollisionAppendsSuffix() {
        when(tenantRepository.existsByName(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(tenantRepository.existsBySlug("acme-corp")).thenReturn(true);
        when(tenantRepository.existsBySlug("acme-corp-2")).thenReturn(false);
        when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCase(anyString()))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$12$hashed");
        stubProvision();

        TenantOnboardingResponse response = service.register(validCommand());

        assertThat(response.getSlug()).isEqualTo("acme-corp-2");
    }

    @Test
    @DisplayName("admin email already registered → DuplicateEmailException (no tenant escalation)")
    void adminEmailAlreadyExists() {
        when(tenantRepository.existsByName(anyString())).thenReturn(false);
        when(userRepository.existsByEmail("admin@acme.example")).thenReturn(true);

        assertThatThrownBy(() -> service.register(validCommand()))
                .isInstanceOf(DuplicateEmailException.class);
        verifyNoInteractions(tenantProvisioningPort, emailService);
    }

    @Test
    @DisplayName("email domain already claimed → TenantEmailDomainConflictException (409)")
    void domainAlreadyClaimed() {
        when(tenantRepository.existsByName(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);
        when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCase("acme.example"))
                .thenReturn(Optional.of(mock(TenantEmailDomain.class)));

        assertThatThrownBy(() -> service.register(validCommand()))
                .isInstanceOf(TenantEmailDomainConflictException.class);
        verifyNoInteractions(tenantProvisioningPort);
    }

    @Test
    @DisplayName("personal/free email provider → PersonalEmailNotAllowedException (422)")
    void blocksPersonalEmail() {
        RegisterTenantCommand cmd = RegisterTenantCommand.builder()
                .orgName("Acme Corp").adminEmail("founder@gmail.com")
                .adminPassword("Sup3rSecret!").adminFirstName("Ada").adminLastName("Lovelace").build();
        when(tenantRepository.existsByName(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);

        assertThatThrownBy(() -> service.register(cmd))
                .isInstanceOf(PersonalEmailNotAllowedException.class);
        verifyNoInteractions(tenantProvisioningPort, emailService);
    }

    @Test
    @DisplayName("wildcard-suffix blocklist entry (gmx.) blocks gmx.de")
    void blocksWildcardSuffixProvider() {
        RegisterTenantCommand cmd = RegisterTenantCommand.builder()
                .orgName("Acme Corp").adminEmail("founder@gmx.de")
                .adminPassword("Sup3rSecret!").adminFirstName("Ada").adminLastName("Lovelace").build();
        when(tenantRepository.existsByName(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);

        assertThatThrownBy(() -> service.register(cmd))
                .isInstanceOf(PersonalEmailNotAllowedException.class);
    }

    @Test
    @DisplayName("disposable provider supplied as emailDomain override → blocked")
    void blocksDisposableOverride() {
        RegisterTenantCommand cmd = RegisterTenantCommand.builder()
                .orgName("Acme Corp").adminEmail("admin@acme.example")
                .emailDomain("mailinator.com")
                .adminPassword("Sup3rSecret!").adminFirstName("Ada").adminLastName("Lovelace").build();
        when(tenantRepository.existsByName(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);

        assertThatThrownBy(() -> service.register(cmd))
                .isInstanceOf(PersonalEmailNotAllowedException.class);
        verifyNoInteractions(tenantProvisioningPort);
    }

    @Test
    @DisplayName("explicit emailDomain override is used + normalised")
    void explicitEmailDomainOverride() {
        RegisterTenantCommand cmd = RegisterTenantCommand.builder()
                .orgName("Acme Corp").adminEmail("admin@acme.example")
                .emailDomain("Acme.Example.COM")
                .adminPassword("Sup3rSecret!").adminFirstName("Ada").adminLastName("Lovelace").build();
        when(tenantRepository.existsByName(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);
        when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCase("acme.example.com"))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$12$hashed");
        stubProvision();

        TenantOnboardingResponse response = service.register(cmd);

        assertThat(response.getEmailDomain()).isEqualTo("acme.example.com");
    }

    @Test
    @DisplayName("mail send failure does not fail the onboarding")
    void emailFailureSwallowed() {
        when(tenantRepository.existsByName(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(tenantRepository.existsBySlug(anyString())).thenReturn(false);
        when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCase(anyString()))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$12$hashed");
        stubProvision();
        doThrow(new RuntimeException("smtp down")).when(emailService)
                .sendTenantOnboardingVerification(anyString(), any(), anyString(), anyString());

        TenantOnboardingResponse response = service.register(validCommand());

        assertThat(response.getStatus()).isEqualTo("TRIAL");
    }
}
