package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.MembershipSwitchPort;
import com.fivucsas.identity.application.port.output.MembershipSwitchPort.SwitchTargetView;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.MembershipNotSwitchableException;
import com.fivucsas.identity.domain.exception.MembershipSwitchForbiddenException;
import com.fivucsas.identity.dto.AuthResponse;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Security tests for {@link SwitchMembershipService} — Phase-5 in-session
 * membership switch. This is an auth-escalation surface; the same-identity HARD
 * GATE is the only barrier between accounts, so it carries the most assertions.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SwitchMembershipService — Phase 5 membership switch")
class SwitchMembershipServiceTest {

    @Mock private MembershipSwitchPort switchPort;
    @Mock private UserRepository userRepository;
    @Mock private AuditLogPort auditLogPort;

    private UUID callerUserId;
    private UUID callerIdentityId;
    private UUID targetUserId;
    private UUID targetTenantId;

    private static final List<String> CALLER_AMR = List.of("pwd", "otp");
    private static final Long CALLER_AUTH_TIME = 1_700_000_000L;
    private static final String IP = "203.0.113.7";
    private static final String UA = "JUnit";

    @BeforeEach
    void setUp() {
        callerUserId = UUID.randomUUID();
        callerIdentityId = UUID.randomUUID();
        targetUserId = UUID.randomUUID();
        targetTenantId = UUID.randomUUID();
    }

    private SwitchMembershipService service(boolean requireStepUp) {
        return new SwitchMembershipService(switchPort, userRepository, auditLogPort, requireStepUp);
    }

    private SwitchTargetView target(UUID identityId, boolean userActive, boolean tenantActive) {
        return new SwitchTargetView(targetUserId, identityId, "target@marun.edu.tr",
                targetTenantId, userActive, tenantActive);
    }

    private AuthResponse mintedResponse() {
        return AuthResponse.of("new-access", "new-refresh", 900_000L,
                UserResponse.builder().id(targetUserId.toString()).email("target@marun.edu.tr").build());
    }

    // (a) same-identity target → new token carries target user_id + tenant + roles, amr/auth_time carried
    @Test
    @DisplayName("(a) same-identity target → mints token AS target; amr/auth_time/act carried")
    void sameIdentityTargetMintsTokenAsTarget() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(callerIdentityId, true, true)));
        when(switchPort.mintSwitchedTokens(eq(targetUserId), eq(CALLER_AMR), eq(CALLER_AUTH_TIME),
                eq(callerUserId), eq(IP), eq(UA))).thenReturn(mintedResponse());

        AuthResponse resp = service(false).switchMembership(
                callerUserId, targetUserId, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA);

        assertThat(resp.getAccessToken()).isEqualTo("new-access");
        assertThat(resp.getRefreshToken()).isEqualTo("new-refresh");
        assertThat(resp.getUser().getId()).isEqualTo(targetUserId.toString());
        // The mint is AS the target, carrying the caller's amr/auth_time and act=caller.
        verify(switchPort).mintSwitchedTokens(targetUserId, CALLER_AMR, CALLER_AUTH_TIME,
                callerUserId, IP, UA);
    }

    // (b) DIFFERENT-identity target → 403, NO token minted
    @Test
    @DisplayName("(b) different-identity target → 403, NO token minted, denial audited")
    void differentIdentityTargetForbiddenNoToken() {
        UUID foreignIdentity = UUID.randomUUID();
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(foreignIdentity, true, true)));

        assertThatThrownBy(() -> service(false).switchMembership(
                callerUserId, targetUserId, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA))
                .isInstanceOf(MembershipSwitchForbiddenException.class);

        verify(switchPort, never()).mintSwitchedTokens(any(), any(), any(), any(), any(), any());
        verify(auditLogPort).logSecurityEvent(eq(callerUserId.toString()),
                eq("MEMBERSHIP_SWITCH_DENIED"), anyString(), anyString());
    }

    // (c) target with NULL identity → 403
    @Test
    @DisplayName("(c) target with NULL identity → 403, NO token minted")
    void nullIdentityTargetForbidden() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(null, true, true)));

        assertThatThrownBy(() -> service(false).switchMembership(
                callerUserId, targetUserId, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA))
                .isInstanceOf(MembershipSwitchForbiddenException.class);

        verify(switchPort, never()).mintSwitchedTokens(any(), any(), any(), any(), any(), any());
    }

    // (d) inactive/locked target → 409
    @Test
    @DisplayName("(d1) inactive/locked target → 409, NO token minted")
    void inactiveTargetConflict() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(callerIdentityId, false, true)));

        assertThatThrownBy(() -> service(false).switchMembership(
                callerUserId, targetUserId, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA))
                .isInstanceOf(MembershipNotSwitchableException.class);

        verify(switchPort, never()).mintSwitchedTokens(any(), any(), any(), any(), any(), any());
    }

    // (d) suspended target tenant → 409
    @Test
    @DisplayName("(d2) suspended target tenant → 409, NO token minted")
    void suspendedTenantConflict() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(callerIdentityId, true, false)));

        assertThatThrownBy(() -> service(false).switchMembership(
                callerUserId, targetUserId, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA))
                .isInstanceOf(MembershipNotSwitchableException.class);

        verify(switchPort, never()).mintSwitchedTokens(any(), any(), any(), any(), any(), any());
    }

    // (e) step-up flag ON + wrong password → rejected, no token
    @Test
    @DisplayName("(e1) step-up ON + wrong password → rejected, NO token minted")
    void stepUpWrongPasswordRejected() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(callerIdentityId, true, true)));
        when(switchPort.verifyPassword(callerUserId, "wrong")).thenReturn(false);

        assertThatThrownBy(() -> service(true).switchMembership(
                callerUserId, targetUserId, "wrong", CALLER_AMR, CALLER_AUTH_TIME, IP, UA))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(switchPort, never()).mintSwitchedTokens(any(), any(), any(), any(), any(), any());
        verify(auditLogPort).logSecurityEvent(eq(callerUserId.toString()),
                eq("MEMBERSHIP_SWITCH_STEPUP_FAILED"), anyString(), anyString());
    }

    @Test
    @DisplayName("(e2) step-up ON + correct password → mints token AS target")
    void stepUpCorrectPasswordMints() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(callerIdentityId, true, true)));
        when(switchPort.verifyPassword(callerUserId, "correct")).thenReturn(true);
        when(switchPort.mintSwitchedTokens(eq(targetUserId), any(), any(), eq(callerUserId),
                anyString(), anyString())).thenReturn(mintedResponse());

        AuthResponse resp = service(true).switchMembership(
                callerUserId, targetUserId, "correct", CALLER_AMR, CALLER_AUTH_TIME, IP, UA);

        assertThat(resp.getAccessToken()).isEqualTo("new-access");
        verify(switchPort).mintSwitchedTokens(targetUserId, CALLER_AMR, CALLER_AUTH_TIME,
                callerUserId, IP, UA);
    }

    @Test
    @DisplayName("(e3) step-up OFF → password ignored, no verifyPassword call")
    void stepUpOffIgnoresPassword() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(callerIdentityId, true, true)));
        when(switchPort.mintSwitchedTokens(any(), any(), any(), any(), any(), any()))
                .thenReturn(mintedResponse());

        service(false).switchMembership(
                callerUserId, targetUserId, "whatever", CALLER_AMR, CALLER_AUTH_TIME, IP, UA);

        verify(switchPort, never()).verifyPassword(any(), anyString());
    }

    // (f) audit emitted with caller as actor
    @Test
    @DisplayName("(f) success audits MEMBERSHIP_SWITCHED with caller as actor + target tenant as resource")
    void successAuditsWithCallerAsActor() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(callerIdentityId, true, true)));
        when(switchPort.mintSwitchedTokens(any(), any(), any(), any(), any(), any()))
                .thenReturn(mintedResponse());

        service(false).switchMembership(
                callerUserId, targetUserId, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA);

        ArgumentCaptor<String> actor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> event = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> tenant = ArgumentCaptor.forClass(String.class);
        verify(auditLogPort).logTenantManagementEvent(actor.capture(), event.capture(),
                tenant.capture(), anyString());
        assertThat(actor.getValue()).isEqualTo(callerUserId.toString());
        assertThat(event.getValue()).isEqualTo("MEMBERSHIP_SWITCHED");
        // Resource is the TARGET TENANT — never the tenant id in the actor slot.
        assertThat(tenant.getValue()).isEqualTo(targetTenantId.toString());
        assertThat(actor.getValue()).isNotEqualTo(targetTenantId.toString());
    }

    @Test
    @DisplayName("HARD GATE runs BEFORE switchability — cross-identity inactive target is 403 not 409")
    void hardGateBeforeSwitchability() {
        UUID foreignIdentity = UUID.randomUUID();
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        // target is BOTH foreign-identity AND inactive — the 403 must win.
        when(switchPort.findSwitchTarget(targetUserId))
                .thenReturn(Optional.of(target(foreignIdentity, false, false)));

        assertThatThrownBy(() -> service(false).switchMembership(
                callerUserId, targetUserId, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA))
                .isInstanceOf(MembershipSwitchForbiddenException.class);
    }

    @Test
    @DisplayName("caller without identity → 403 (cannot resolve own identity)")
    void callerWithoutIdentityForbidden() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service(false).switchMembership(
                callerUserId, targetUserId, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA))
                .isInstanceOf(MembershipSwitchForbiddenException.class);

        verify(switchPort, never()).mintSwitchedTokens(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("switch to self (no-op) → mints a fresh session for the SAME membership")
    void switchToSelfMintsFreshSession() {
        when(userRepository.findIdentityIdById(callerUserId)).thenReturn(Optional.of(callerIdentityId));
        // self target carries the caller's own user id + identity.
        SwitchTargetView self = new SwitchTargetView(callerUserId, callerIdentityId,
                "caller@marun.edu.tr", targetTenantId, true, true);
        when(switchPort.findSwitchTarget(callerUserId)).thenReturn(Optional.of(self));
        when(switchPort.mintSwitchedTokens(eq(callerUserId), any(), any(), eq(callerUserId),
                anyString(), anyString())).thenReturn(mintedResponse());

        AuthResponse resp = service(false).switchMembership(
                callerUserId, callerUserId, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA);

        assertThat(resp.getAccessToken()).isEqualTo("new-access");
        verify(switchPort).mintSwitchedTokens(callerUserId, CALLER_AMR, CALLER_AUTH_TIME,
                callerUserId, IP, UA);
    }

    @Test
    @DisplayName("null targetUserId → 400 (IllegalArgumentException)")
    void nullTargetIsBadRequest() {
        lenient().when(userRepository.findIdentityIdById(callerUserId))
                .thenReturn(Optional.of(callerIdentityId));

        assertThatThrownBy(() -> service(false).switchMembership(
                callerUserId, null, null, CALLER_AMR, CALLER_AUTH_TIME, IP, UA))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
