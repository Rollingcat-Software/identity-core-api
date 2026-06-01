package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.IdentityMeResponse;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.IdentityLinkUserPort;
import com.fivucsas.identity.application.port.output.IdentityLinkUserPort.MembershipView;
import com.fivucsas.identity.domain.exception.IdentityLinkException;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.ResourceNotFoundException;
import com.fivucsas.identity.entity.Identity;
import com.fivucsas.identity.entity.IdentityEmail;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.email.OtpPurpose;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.repository.IdentityEmailRepository;
import com.fivucsas.identity.repository.IdentityRepository;
import com.fivucsas.identity.security.RateLimitService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("IdentityLinkService — Phase 2 account linking")
class IdentityLinkServiceTest {

    @Mock private IdentityLinkUserPort userPort;
    @Mock private IdentityRepository identityRepository;
    @Mock private IdentityEmailRepository identityEmailRepository;
    @Mock private OtpService otpService;
    @Mock private EmailService emailService;
    @Mock private RateLimitService rateLimitService;
    @Mock private AuditLogPort auditLogPort;

    @InjectMocks private IdentityLinkService service;

    private UUID callerUserId;
    private UUID callerIdentityId;
    private UUID targetUserId;
    private UUID targetIdentityId;
    private UUID callerTenantId;
    private UUID targetTenantId;
    private final String targetEmail = "target@marun.edu.tr";

    @BeforeEach
    void setUp() {
        callerUserId = UUID.randomUUID();
        callerIdentityId = UUID.randomUUID();
        targetUserId = UUID.randomUUID();
        targetIdentityId = UUID.randomUUID();
        callerTenantId = UUID.randomUUID();
        targetTenantId = UUID.randomUUID();
    }

    private MembershipView caller() {
        return new MembershipView(callerUserId, callerIdentityId, "caller@fivucsas.com",
                callerTenantId, "Fivucsas", "TENANT_ADMIN", true);
    }

    private MembershipView target(boolean active) {
        return new MembershipView(targetUserId, targetIdentityId, targetEmail,
                targetTenantId, "Marmara", "TENANT_ADMIN", active);
    }

    // ---- initiate ----------------------------------------------------------

    @Test
    @DisplayName("initiate: happy path sends OTP to the target email and audits")
    void initiateHappyPath() {
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(rateLimitService.allowPasswordResetAttempt(anyString())).thenReturn(true);
        when(userPort.findMembershipByEmail(targetEmail)).thenReturn(Optional.of(target(true)));
        when(userPort.findMembershipsByIdentityId(callerIdentityId))
                .thenReturn(List.of(caller())); // caller is in a different tenant
        when(otpService.generate(anyString())).thenReturn("123456");

        service.initiateLink(callerUserId, "  Target@Marun.edu.tr  ");

        verify(emailService).sendOtp(eq(targetEmail), eq("123456"), eq(OtpPurpose.ACCOUNT_LINK), eq(null));
        verify(auditLogPort).logSecurityEvent(eq(callerUserId.toString()),
                eq("IDENTITY_LINK_INITIATED"), any(), anyString());
    }

    @Test
    @DisplayName("initiate: same-tenant target is blocked (would duplicate a membership)")
    void initiateSameTenantBlocked() {
        // Target lives in the SAME tenant the caller already belongs to.
        MembershipView sameTenantTarget = new MembershipView(targetUserId, targetIdentityId,
                targetEmail, callerTenantId, "Fivucsas", "TENANT_MEMBER", true);
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(rateLimitService.allowPasswordResetAttempt(anyString())).thenReturn(true);
        when(userPort.findMembershipByEmail(targetEmail)).thenReturn(Optional.of(sameTenantTarget));
        when(userPort.findMembershipsByIdentityId(callerIdentityId)).thenReturn(List.of(caller()));

        assertThatThrownBy(() -> service.initiateLink(callerUserId, targetEmail))
                .isInstanceOf(IdentityLinkException.class)
                .hasMessageContaining("same");

        verify(emailService, never()).sendOtp(anyString(), anyString(), any(), any());
    }

    @Test
    @DisplayName("initiate: inactive target membership is rejected")
    void initiateInactiveTarget() {
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(rateLimitService.allowPasswordResetAttempt(anyString())).thenReturn(true);
        when(userPort.findMembershipByEmail(targetEmail)).thenReturn(Optional.of(target(false)));

        assertThatThrownBy(() -> service.initiateLink(callerUserId, targetEmail))
                .isInstanceOf(IdentityLinkException.class)
                .hasMessageContaining("not active");
    }

    @Test
    @DisplayName("initiate: unknown target email is 404")
    void initiateUnknownTarget() {
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(rateLimitService.allowPasswordResetAttempt(anyString())).thenReturn(true);
        when(userPort.findMembershipByEmail(targetEmail)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.initiateLink(callerUserId, targetEmail))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    @DisplayName("initiate: rate limit exceeded is rejected before any email is sent")
    void initiateRateLimited() {
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(rateLimitService.allowPasswordResetAttempt(anyString())).thenReturn(false);

        assertThatThrownBy(() -> service.initiateLink(callerUserId, targetEmail))
                .isInstanceOf(IdentityLinkException.class);

        verify(userPort, never()).findMembershipByEmail(anyString());
        verify(emailService, never()).sendOtp(anyString(), anyString(), any(), any());
    }

    // ---- confirm -----------------------------------------------------------

    @Test
    @DisplayName("confirm: happy path re-points identity, moves email, deletes orphan, audits IDENTITY_LINKED")
    void confirmHappyPath() {
        Identity callerIdentity = Identity.builder().id(callerIdentityId).build();
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(userPort.findMembershipByEmail(targetEmail)).thenReturn(Optional.of(target(true)));
        when(userPort.findMembershipsByIdentityId(callerIdentityId)).thenReturn(List.of(caller()));
        when(otpService.validateWithResult(anyString(), eq("123456")))
                .thenReturn(OtpService.ValidationResult.valid());
        when(userPort.verifyPassword(callerUserId, "caller-pass")).thenReturn(true);
        when(identityRepository.findById(callerIdentityId)).thenReturn(Optional.of(callerIdentity));
        when(identityEmailRepository.findByEmailIgnoreCase(targetEmail)).thenReturn(Optional.empty());
        // Orphan check: target identity now has no remaining members.
        when(userPort.findMembershipsByIdentityId(targetIdentityId)).thenReturn(List.of());
        when(identityEmailRepository.findByIdentityId(targetIdentityId)).thenReturn(List.of());

        service.confirmLink(callerUserId, targetEmail, "123456", "caller-pass");

        verify(userPort).repointIdentity(targetUserId, callerIdentityId);
        ArgumentCaptor<IdentityEmail> emailCaptor = ArgumentCaptor.forClass(IdentityEmail.class);
        verify(identityEmailRepository).save(emailCaptor.capture());
        assertThat(emailCaptor.getValue().getEmail()).isEqualTo(targetEmail);
        assertThat(emailCaptor.getValue().isVerified()).isTrue();
        verify(identityRepository).deleteById(targetIdentityId);
        verify(auditLogPort).logSecurityEvent(eq(callerUserId.toString()),
                eq("IDENTITY_LINKED"), any(), anyString());
    }

    @Test
    @DisplayName("confirm: invalid OTP fails (InvalidCredentials) and never re-points")
    void confirmOtpFail() {
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(userPort.findMembershipByEmail(targetEmail)).thenReturn(Optional.of(target(true)));
        when(userPort.findMembershipsByIdentityId(callerIdentityId)).thenReturn(List.of(caller()));
        when(otpService.validateWithResult(anyString(), anyString()))
                .thenReturn(OtpService.ValidationResult.invalid(4));

        assertThatThrownBy(() -> service.confirmLink(callerUserId, targetEmail, "000000", "caller-pass"))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userPort, never()).repointIdentity(any(), any());
        verify(userPort, never()).verifyPassword(any(), anyString());
    }

    @Test
    @DisplayName("confirm: valid OTP but failed step-up password is rejected and never re-points")
    void confirmStepUpFail() {
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(userPort.findMembershipByEmail(targetEmail)).thenReturn(Optional.of(target(true)));
        when(userPort.findMembershipsByIdentityId(callerIdentityId)).thenReturn(List.of(caller()));
        when(otpService.validateWithResult(anyString(), eq("123456")))
                .thenReturn(OtpService.ValidationResult.valid());
        when(userPort.verifyPassword(callerUserId, "wrong-pass")).thenReturn(false);

        assertThatThrownBy(() -> service.confirmLink(callerUserId, targetEmail, "123456", "wrong-pass"))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userPort, never()).repointIdentity(any(), any());
    }

    @Test
    @DisplayName("confirm: idempotent no-op when already linked to the caller's identity")
    void confirmIdempotent() {
        MembershipView alreadyLinked = new MembershipView(targetUserId, callerIdentityId,
                targetEmail, targetTenantId, "Marmara", "TENANT_ADMIN", true);
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(userPort.findMembershipByEmail(targetEmail)).thenReturn(Optional.of(alreadyLinked));

        service.confirmLink(callerUserId, targetEmail, "irrelevant", "irrelevant");

        verify(otpService, never()).validateWithResult(anyString(), anyString());
        verify(userPort, never()).repointIdentity(any(), any());
    }

    // ---- unlink ------------------------------------------------------------

    @Test
    @DisplayName("unlink: splits the membership into a fresh identity + email and audits IDENTITY_UNLINKED")
    void unlinkHappyPath() {
        // Membership currently in the caller's identity.
        MembershipView member = new MembershipView(targetUserId, callerIdentityId, targetEmail,
                targetTenantId, "Marmara", "TENANT_ADMIN", true);
        UUID freshIdentityId = UUID.randomUUID();
        Identity fresh = Identity.builder().id(freshIdentityId).build();
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(userPort.findMembershipByUserId(targetUserId)).thenReturn(Optional.of(member));
        when(identityRepository.save(any(Identity.class))).thenReturn(fresh);
        when(identityRepository.findById(freshIdentityId)).thenReturn(Optional.of(fresh));
        when(identityEmailRepository.findByEmailIgnoreCase(targetEmail)).thenReturn(Optional.empty());

        service.unlink(callerUserId, targetUserId);

        verify(userPort).repointIdentity(targetUserId, freshIdentityId);
        verify(identityEmailRepository).save(any(IdentityEmail.class));
        verify(auditLogPort).logSecurityEvent(eq(callerUserId.toString()),
                eq("IDENTITY_UNLINKED"), any(), anyString());
    }

    @Test
    @DisplayName("unlink: caller cannot unlink a membership outside their own identity")
    void unlinkForeignMembershipBlocked() {
        MembershipView foreign = new MembershipView(targetUserId, targetIdentityId, targetEmail,
                targetTenantId, "Marmara", "TENANT_ADMIN", true);
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(userPort.findMembershipByUserId(targetUserId)).thenReturn(Optional.of(foreign));

        assertThatThrownBy(() -> service.unlink(callerUserId, targetUserId))
                .isInstanceOf(IdentityLinkException.class)
                .hasMessageContaining("your own identity");

        verify(userPort, never()).repointIdentity(any(), any());
        verify(identityRepository, never()).save(any());
    }

    // ---- /me ---------------------------------------------------------------

    @Test
    @DisplayName("/me: returns the caller's identity, emails, and cross-tenant memberships")
    void getMyIdentityShape() {
        MembershipView m1 = caller();
        MembershipView m2 = new MembershipView(targetUserId, callerIdentityId, targetEmail,
                targetTenantId, "Marmara", "TENANT_ADMIN", true);
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.of(caller()));
        when(userPort.findMembershipsByIdentityId(callerIdentityId)).thenReturn(List.of(m1, m2));
        IdentityEmail e1 = IdentityEmail.builder().email("caller@fivucsas.com").verified(true).build();
        IdentityEmail e2 = IdentityEmail.builder().email(targetEmail).verified(true).build();
        when(identityEmailRepository.findByIdentityId(callerIdentityId)).thenReturn(List.of(e1, e2));

        IdentityMeResponse response = service.getMyIdentity(callerUserId);

        assertThat(response.identityId()).isEqualTo(callerIdentityId);
        assertThat(response.memberships()).hasSize(2);
        assertThat(response.memberships()).extracting(IdentityMeResponse.MembershipView::tenantName)
                .containsExactlyInAnyOrder("Fivucsas", "Marmara");
        assertThat(response.emails()).hasSize(2);
        assertThat(response.emails()).extracting(IdentityMeResponse.EmailView::email)
                .containsExactlyInAnyOrder("caller@fivucsas.com", targetEmail);
    }

    @Test
    @DisplayName("/me: unknown caller is 404 (defensive)")
    void getMyIdentityUnknownCaller() {
        when(userPort.findMembershipByUserId(callerUserId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getMyIdentity(callerUserId))
                .isInstanceOf(ResourceNotFoundException.class);
    }
}
