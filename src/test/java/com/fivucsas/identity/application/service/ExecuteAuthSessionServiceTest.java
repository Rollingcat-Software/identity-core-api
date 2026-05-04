package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CompleteAuthStepCommand;
import com.fivucsas.identity.application.dto.command.StartAuthSessionCommand;
import com.fivucsas.identity.application.dto.response.AuthSessionResponse;
import com.fivucsas.identity.application.dto.response.StepResultResponse;
import com.fivucsas.identity.application.port.output.*;
import com.fivucsas.identity.application.service.handler.AuthMethodHandler;
import com.fivucsas.identity.application.service.handler.StepResult;
import com.fivucsas.identity.domain.model.auth.*;
import com.fivucsas.identity.entity.*;
import com.fivucsas.identity.exception.DomainStateConflictException;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.service.RefreshTokenService;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ExecuteAuthSessionServiceTest {

    @Mock private AuthSessionRepositoryPort authSessionRepository;
    @Mock private AuthSessionStepRepositoryPort authSessionStepRepository;
    @Mock private AuthFlowRepositoryPort authFlowRepository;
    @Mock private AuthFlowStepRepositoryPort authFlowStepRepository;
    @Mock private JpaTenantRepository tenantRepository;
    @Mock private UserRepository userRepository;
    @Mock private AuthMethodHandlerRegistry handlerRegistry;
    @Mock private TokenGenerationPort tokenGenerator;
    @Mock private AuditLogPort auditLogPort;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private EnrollmentHealthService enrollmentHealthService;

    @InjectMocks
    private ExecuteAuthSessionService service;

    @Test
    void startSession_WhenTenantNotFound_ShouldThrowEntityNotFoundException() {
        // given
        when(tenantRepository.findBySlug("unknown")).thenReturn(Optional.empty());

        StartAuthSessionCommand command = new StartAuthSessionCommand(
                "unknown", OperationType.APP_LOGIN, "WEB", null, null, "127.0.0.1", "test-agent");

        // when/then
        assertThatThrownBy(() -> service.startSession(command))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessageContaining("Tenant not found");
    }

    @Test
    void startSession_WhenNoDefaultFlow_ShouldThrowEntityNotFoundException() {
        // given
        Tenant tenant = mock(Tenant.class);
        UUID tenantId = UUID.randomUUID();
        when(tenant.getId()).thenReturn(tenantId);
        when(tenantRepository.findBySlug("test-tenant")).thenReturn(Optional.of(tenant));
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(tenantId, OperationType.APP_LOGIN))
                .thenReturn(Optional.empty());

        StartAuthSessionCommand command = new StartAuthSessionCommand(
                "test-tenant", OperationType.APP_LOGIN, "WEB", null, null, "127.0.0.1", "agent");

        // when/then
        assertThatThrownBy(() -> service.startSession(command))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessageContaining("No default auth flow");
    }

    @Test
    void startSession_WhenAppLoginWithNonPasswordFirstStep_ShouldSucceed() {
        // After removing the PASSWORD-first constraint (2026-04-24), tenants are
        // free to configure ANY AuthMethodType as step[0] for every OperationType.
        // A flow starting with FACE_LIVENESS must now create a session cleanly.
        Tenant tenant = mock(Tenant.class);
        UUID tenantId = UUID.randomUUID();
        when(tenant.getId()).thenReturn(tenantId);
        when(tenant.getSlug()).thenReturn("test-tenant");
        when(tenantRepository.findBySlug("test-tenant")).thenReturn(Optional.of(tenant));

        AuthFlow flow = mock(AuthFlow.class);
        UUID flowId = UUID.randomUUID();
        when(flow.getId()).thenReturn(flowId);
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(tenantId, OperationType.APP_LOGIN))
                .thenReturn(Optional.of(flow));

        // First step is FACE — should now be accepted.
        AuthFlowStep step = mock(AuthFlowStep.class);
        AuthMethod authMethod = mock(AuthMethod.class);
        when(authMethod.getType()).thenReturn(AuthMethodType.FACE);
        when(step.getAuthMethod()).thenReturn(authMethod);
        when(authFlowStepRepository.findAllByAuthFlowIdOrderByStepOrderAsc(flowId))
                .thenReturn(List.of(step));

        AuthSession savedSession = mock(AuthSession.class);
        UUID sessionId = UUID.randomUUID();
        when(savedSession.getId()).thenReturn(sessionId);
        when(savedSession.getAuthFlow()).thenReturn(flow);
        when(flow.getStepCount()).thenReturn(1);
        when(authSessionRepository.save(any())).thenReturn(savedSession);
        when(authSessionRepository.findById(sessionId)).thenReturn(Optional.of(savedSession));

        StartAuthSessionCommand command = new StartAuthSessionCommand(
                "test-tenant", OperationType.APP_LOGIN, "WEB", null, null, "127.0.0.1", "agent");

        AuthSessionResponse response = service.startSession(command);

        assertThat(response).isNotNull();
        verify(authSessionStepRepository).save(any());
    }

    @Test
    void startSession_WhenFirstStepHasNoAuthMethod_ShouldThrowIllegalState() {
        // Structural check: a step with null AuthMethod is a corrupt flow and must fail loud.
        Tenant tenant = mock(Tenant.class);
        UUID tenantId = UUID.randomUUID();
        when(tenant.getId()).thenReturn(tenantId);
        when(tenantRepository.findBySlug("test-tenant")).thenReturn(Optional.of(tenant));

        AuthFlow flow = mock(AuthFlow.class);
        UUID flowId = UUID.randomUUID();
        when(flow.getId()).thenReturn(flowId);
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(tenantId, OperationType.APP_LOGIN))
                .thenReturn(Optional.of(flow));

        AuthFlowStep step = mock(AuthFlowStep.class);
        when(step.getAuthMethod()).thenReturn(null);
        when(authFlowStepRepository.findAllByAuthFlowIdOrderByStepOrderAsc(flowId))
                .thenReturn(List.of(step));

        StartAuthSessionCommand command = new StartAuthSessionCommand(
                "test-tenant", OperationType.APP_LOGIN, "WEB", null, null, "127.0.0.1", "agent");

        assertThatThrownBy(() -> service.startSession(command))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no valid AuthMethod");
    }

    @Test
    void startSession_WhenFlowHasNoSteps_ShouldThrowIllegalState() {
        Tenant tenant = mock(Tenant.class);
        UUID tenantId = UUID.randomUUID();
        when(tenant.getId()).thenReturn(tenantId);
        when(tenantRepository.findBySlug("test-tenant")).thenReturn(Optional.of(tenant));

        AuthFlow flow = mock(AuthFlow.class);
        UUID flowId = UUID.randomUUID();
        when(flow.getId()).thenReturn(flowId);
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(tenantId, OperationType.APP_LOGIN))
                .thenReturn(Optional.of(flow));
        when(authFlowStepRepository.findAllByAuthFlowIdOrderByStepOrderAsc(flowId))
                .thenReturn(List.of());

        StartAuthSessionCommand command = new StartAuthSessionCommand(
                "test-tenant", OperationType.APP_LOGIN, "WEB", null, null, "127.0.0.1", "agent");

        assertThatThrownBy(() -> service.startSession(command))
                .isInstanceOf(DomainStateConflictException.class)
                .hasMessageContaining("no steps configured");
    }

    @Test
    void getSessionStatus_WhenSessionNotFound_ShouldThrow() {
        // given
        UUID sessionId = UUID.randomUUID();
        when(authSessionRepository.findById(sessionId)).thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.getSessionStatus(sessionId))
                .isInstanceOf(EntityNotFoundException.class);
    }

    @Test
    void completeStep_WhenSessionExpired_ShouldThrowIllegalState() {
        // given
        UUID sessionId = UUID.randomUUID();
        AuthSession session = mock(AuthSession.class);
        when(session.isExpired()).thenReturn(true);
        when(authSessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.of(session));

        CompleteAuthStepCommand command = new CompleteAuthStepCommand(Map.of("key", "value"));

        // when/then
        assertThatThrownBy(() -> service.completeStep(sessionId, 1, command))
                .isInstanceOf(DomainStateConflictException.class)
                .hasMessageContaining("expired");

        verify(session).markExpired();
        verify(authSessionRepository).save(session);
    }

    @Test
    void completeStep_WhenSessionTerminal_ShouldThrowIllegalState() {
        // given
        UUID sessionId = UUID.randomUUID();
        AuthSession session = mock(AuthSession.class);
        when(session.isExpired()).thenReturn(false);
        when(session.isTerminal()).thenReturn(true);
        when(session.getStatus()).thenReturn(AuthSessionStatus.COMPLETED);
        when(authSessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.of(session));

        CompleteAuthStepCommand command = new CompleteAuthStepCommand(Map.of());

        // when/then
        assertThatThrownBy(() -> service.completeStep(sessionId, 1, command))
                .isInstanceOf(DomainStateConflictException.class)
                .hasMessageContaining("terminal state");
    }

    @Test
    void cancelSession_WhenSessionExists_ShouldCancelAndSave() {
        // given
        UUID sessionId = UUID.randomUUID();
        AuthSession session = mock(AuthSession.class);
        when(authSessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.of(session));

        // when
        service.cancelSession(sessionId);

        // then
        verify(session).cancel();
        verify(authSessionRepository).save(session);
    }

    @Test
    void cancelSession_WhenSessionNotFound_ShouldThrow() {
        // given
        UUID sessionId = UUID.randomUUID();
        when(authSessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.cancelSession(sessionId))
                .isInstanceOf(EntityNotFoundException.class);
    }

    @Test
    void skipStep_WhenStepRequired_ShouldThrowIllegalState() {
        // given
        UUID sessionId = UUID.randomUUID();
        AuthSession session = mock(AuthSession.class);
        when(authSessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.of(session));

        AuthFlowStep flowStep = mock(AuthFlowStep.class);
        when(flowStep.getStepOrder()).thenReturn(1);
        when(flowStep.isRequired()).thenReturn(true);

        AuthSessionStep sessionStep = mock(AuthSessionStep.class);
        when(sessionStep.getAuthFlowStep()).thenReturn(flowStep);
        when(authSessionStepRepository.findAllBySessionId(sessionId)).thenReturn(List.of(sessionStep));

        // when/then
        assertThatThrownBy(() -> service.skipStep(sessionId, 1))
                .isInstanceOf(DomainStateConflictException.class)
                .hasMessageContaining("Cannot skip required step");
    }

    // ============== Post-audit 2026-04-24 login edge cases ==============

    @Test
    void tryCancelSession_WhenSessionExists_ShouldCancelAndReturnTrue() {
        // Edge case #3: idempotent DELETE — first call cancels and returns true.
        UUID sessionId = UUID.randomUUID();
        AuthSession session = mock(AuthSession.class);
        when(session.isTerminal()).thenReturn(false);
        when(authSessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.of(session));

        boolean existed = service.tryCancelSession(sessionId);

        assertThat(existed).isTrue();
        verify(session).cancel();
        verify(authSessionRepository).save(session);
    }

    @Test
    void tryCancelSession_WhenAlreadyTerminal_ShouldNoOpAndReturnTrue() {
        // Edge case #3: repeating DELETE after a successful first call must
        // still return true (→ controller emits 204) — terminal sessions are
        // NOT re-transitioned, but we don't pretend they don't exist either.
        UUID sessionId = UUID.randomUUID();
        AuthSession session = mock(AuthSession.class);
        when(session.isTerminal()).thenReturn(true);
        when(session.getStatus()).thenReturn(AuthSessionStatus.CANCELLED);
        when(authSessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.of(session));

        boolean existed = service.tryCancelSession(sessionId);

        assertThat(existed).isTrue();
        verify(session, never()).cancel();
        verify(authSessionRepository, never()).save(any());
    }

    @Test
    void tryCancelSession_WhenUnknownId_ShouldReturnFalse() {
        // Edge case #3: unknown id → controller emits 404, NOT 500.
        UUID sessionId = UUID.randomUUID();
        when(authSessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.empty());

        boolean existed = service.tryCancelSession(sessionId);

        assertThat(existed).isFalse();
        verify(authSessionRepository, never()).save(any());
    }

    @Test
    void startSession_WhenUserMissingRequiredEnrollment_ShouldThrowNeedsEnrollment() {
        // Edge cases #1 + #6: pre-flight enrollment check must trip before the
        // session row is written, so the user is never trapped past step 0 on
        // an un-enrollable required step. Replicates the original Marmara
        // walkthrough: 3 required steps, 0 enrollments, user resolves by email.
        Tenant tenant = mock(Tenant.class);
        UUID tenantId = UUID.randomUUID();
        when(tenant.getId()).thenReturn(tenantId);
        when(tenantRepository.findBySlug("marmara")).thenReturn(Optional.of(tenant));

        AuthFlow flow = mock(AuthFlow.class);
        UUID flowId = UUID.randomUUID();
        when(flow.getId()).thenReturn(flowId);
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                tenantId, OperationType.APP_LOGIN))
                .thenReturn(Optional.of(flow));

        // Step 1 = PASSWORD (no-enrollment), step 2 = TOTP (REQUIRED, user not
        // enrolled). The pre-flight check must surface step 2 as the dead-end.
        AuthMethod password = mock(AuthMethod.class);
        when(password.getType()).thenReturn(AuthMethodType.PASSWORD);
        AuthFlowStep step1 = mock(AuthFlowStep.class);
        when(step1.getAuthMethod()).thenReturn(password);
        when(step1.isRequired()).thenReturn(true);
        when(step1.getAvailableMethods()).thenReturn(List.of(password));
        when(password.isRequiresEnrollment()).thenReturn(false);

        AuthMethod totp = mock(AuthMethod.class);
        when(totp.getType()).thenReturn(AuthMethodType.TOTP);
        when(totp.isRequiresEnrollment()).thenReturn(true);
        AuthFlowStep step2 = mock(AuthFlowStep.class);
        when(step2.isRequired()).thenReturn(true);
        when(step2.getAvailableMethods()).thenReturn(List.of(totp));
        when(step2.getFallbackMethod()).thenReturn(null);

        when(authFlowStepRepository.findAllByAuthFlowIdOrderByStepOrderAsc(flowId))
                .thenReturn(List.of(step1, step2));

        User user = mock(User.class);
        UUID userId = UUID.randomUUID();
        when(user.getId()).thenReturn(userId);
        when(userRepository.findByEmail("ahmet@marun.edu.tr")).thenReturn(Optional.of(user));
        // User has zero enrollments — health map empty.
        when(enrollmentHealthService.validateEnrollments(userId)).thenReturn(Map.of());

        StartAuthSessionCommand command = new StartAuthSessionCommand(
                "marmara", OperationType.APP_LOGIN, "WEB", null,
                "ahmet@marun.edu.tr", "127.0.0.1", "agent");

        assertThatThrownBy(() -> service.startSession(command))
                .isInstanceOfSatisfying(
                        com.fivucsas.identity.domain.exception.NeedsEnrollmentException.class,
                        ex -> {
                            assertThat(ex.getMethod()).isEqualTo("TOTP");
                            assertThat(ex.getEnrollmentUrl()).isEqualTo("/enroll/totp");
                        });

        // Critical: NO session row was ever written.
        verify(authSessionRepository, never()).save(any());
        verify(authSessionStepRepository, never()).save(any());
    }
}
