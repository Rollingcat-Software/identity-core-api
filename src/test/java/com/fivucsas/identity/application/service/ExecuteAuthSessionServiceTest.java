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
    void startSession_WhenAppLoginWithoutPasswordFirst_ShouldThrowIllegalState() {
        // given
        Tenant tenant = mock(Tenant.class);
        UUID tenantId = UUID.randomUUID();
        when(tenant.getId()).thenReturn(tenantId);
        when(tenantRepository.findBySlug("test-tenant")).thenReturn(Optional.of(tenant));

        AuthFlow flow = mock(AuthFlow.class);
        UUID flowId = UUID.randomUUID();
        when(flow.getId()).thenReturn(flowId);
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(tenantId, OperationType.APP_LOGIN))
                .thenReturn(Optional.of(flow));

        // First step is FACE, not PASSWORD
        AuthFlowStep step = mock(AuthFlowStep.class);
        AuthMethod authMethod = mock(AuthMethod.class);
        when(authMethod.getType()).thenReturn(AuthMethodType.FACE);
        when(step.getAuthMethod()).thenReturn(authMethod);
        when(authFlowStepRepository.findAllByAuthFlowIdOrderByStepOrderAsc(flowId))
                .thenReturn(List.of(step));

        StartAuthSessionCommand command = new StartAuthSessionCommand(
                "test-tenant", OperationType.APP_LOGIN, "WEB", null, null, "127.0.0.1", "agent");

        // when/then
        assertThatThrownBy(() -> service.startSession(command))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("PASSWORD as the first step");
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
                .isInstanceOf(IllegalStateException.class)
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
                .isInstanceOf(IllegalStateException.class)
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
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Cannot skip required step");
    }
}
