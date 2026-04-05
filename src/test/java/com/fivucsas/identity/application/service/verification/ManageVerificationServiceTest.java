package com.fivucsas.identity.application.service.verification;

import com.fivucsas.identity.application.dto.command.SubmitVerificationStepCommand;
import com.fivucsas.identity.application.dto.response.IndustryTemplateResponse;
import com.fivucsas.identity.application.dto.response.VerificationSessionResponse;
import com.fivucsas.identity.application.dto.response.VerificationStepResultResponse;
import com.fivucsas.identity.application.service.ManageVerificationService;
import com.fivucsas.identity.domain.model.auth.FlowType;
import com.fivucsas.identity.domain.model.auth.VerificationSessionStatus;
import com.fivucsas.identity.domain.model.auth.VerificationStepStatus;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.VerificationSession;
import com.fivucsas.identity.repository.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ManageVerificationServiceTest {

    @Mock private VerificationSessionRepository sessionRepository;
    @Mock private VerificationStepResultRepository stepResultRepository;
    @Mock private VerificationDocumentRepository documentRepository;
    @Mock private AuthFlowRepository authFlowRepository;
    @Mock private UserRepository userRepository;
    @Mock private JpaTenantRepository tenantRepository;
    @Mock private VerificationStepHandlerRegistry handlerRegistry;
    @Spy private ObjectMapper objectMapper = new ObjectMapper();

    @InjectMocks
    private ManageVerificationService service;

    private final UUID userId = UUID.randomUUID();
    private final UUID tenantId = UUID.randomUUID();
    private final UUID flowId = UUID.randomUUID();

    @Test
    void createSession_WhenValidInputs_ShouldCreateSession() {
        // given
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        AuthFlow flow = mock(AuthFlow.class);
        when(flow.getFlowType()).thenReturn(FlowType.VERIFICATION);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));

        VerificationSession savedSession = mock(VerificationSession.class);
        when(savedSession.getId()).thenReturn(UUID.randomUUID());
        when(savedSession.getUser()).thenReturn(user);
        when(savedSession.getTenant()).thenReturn(tenant);
        when(savedSession.getFlow()).thenReturn(flow);
        when(savedSession.getStatus()).thenReturn(VerificationSessionStatus.PENDING);
        when(savedSession.getCurrentStepNumber()).thenReturn(0);
        when(savedSession.getStepResults()).thenReturn(null);
        when(user.getId()).thenReturn(userId);
        when(tenant.getId()).thenReturn(tenantId);
        when(flow.getId()).thenReturn(flowId);
        when(flow.getName()).thenReturn("Test Flow");
        when(sessionRepository.save(any(VerificationSession.class))).thenReturn(savedSession);

        // when
        VerificationSessionResponse result = service.createSession(userId, tenantId, flowId);

        // then
        assertThat(result).isNotNull();
        assertThat(result.status()).isEqualTo(VerificationSessionStatus.PENDING);
        verify(sessionRepository).save(any(VerificationSession.class));
    }

    @Test
    void createSession_WhenUserNotFound_ShouldThrow() {
        // given
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.createSession(userId, tenantId, flowId))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    void createSession_WhenFlowNotVerificationType_ShouldThrow() {
        // given
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        AuthFlow flow = mock(AuthFlow.class);
        when(flow.getFlowType()).thenReturn(FlowType.AUTHENTICATION);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));

        // when/then
        assertThatThrownBy(() -> service.createSession(userId, tenantId, flowId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a VERIFICATION flow");
    }

    @Test
    void getSession_WhenNotFound_ShouldThrow() {
        // given
        UUID sessionId = UUID.randomUUID();
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.getSession(sessionId))
                .isInstanceOf(EntityNotFoundException.class);
    }

    @Test
    void getTemplates_ShouldReturnFiveTemplates() {
        // when
        List<IndustryTemplateResponse> templates = service.getTemplates();

        // then
        assertThat(templates).hasSize(5);
        assertThat(templates).extracting(IndustryTemplateResponse::templateId)
                .contains("FINTECH_KYC", "HEALTHCARE_BASIC", "EDUCATION_AGE", "TELECOM_ONBOARDING", "SIMPLE_DOCUMENT");
    }

    @Test
    void getUserVerificationStatus_WhenUserNotFound_ShouldThrow() {
        // given
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.getUserVerificationStatus(userId))
                .isInstanceOf(EntityNotFoundException.class);
    }

    @Test
    void completeSession_WhenSessionAlreadyTerminal_ShouldThrow() {
        // given
        UUID sessionId = UUID.randomUUID();
        VerificationSession session = mock(VerificationSession.class);
        when(session.isTerminal()).thenReturn(true);
        when(session.getStatus()).thenReturn(VerificationSessionStatus.COMPLETED);
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        // when/then
        assertThatThrownBy(() -> service.completeSession(sessionId))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("terminal state");
    }

    @Test
    void completeSession_WhenStepsFailed_ShouldMarkFailed() {
        // given
        UUID sessionId = UUID.randomUUID();
        VerificationSession session = mock(VerificationSession.class);
        when(session.isTerminal()).thenReturn(false);
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        com.fivucsas.identity.entity.VerificationStepResult failedStep = mock(com.fivucsas.identity.entity.VerificationStepResult.class);
        when(failedStep.getStatus()).thenReturn(VerificationStepStatus.FAILED);
        when(stepResultRepository.findAllBySessionIdOrderByStepNumberAsc(sessionId))
                .thenReturn(List.of(failedStep));

        // Set up for VerificationSessionResponse.from()
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        AuthFlow flow = mock(AuthFlow.class);
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(session.getTenant()).thenReturn(tenant);
        when(session.getFlow()).thenReturn(flow);
        when(session.getStatus()).thenReturn(VerificationSessionStatus.FAILED);
        when(session.getStepResults()).thenReturn(null);
        when(user.getId()).thenReturn(userId);
        when(tenant.getId()).thenReturn(tenantId);
        when(flow.getId()).thenReturn(flowId);
        when(flow.getName()).thenReturn("Flow");

        // when
        VerificationSessionResponse result = service.completeSession(sessionId);

        // then
        verify(session).markFailed();
        verify(sessionRepository).save(session);
    }

    @Test
    void completeSession_WhenNotAllStepsComplete_ShouldThrow() {
        // given
        UUID sessionId = UUID.randomUUID();
        VerificationSession session = mock(VerificationSession.class);
        when(session.isTerminal()).thenReturn(false);
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        com.fivucsas.identity.entity.VerificationStepResult pendingStep = mock(com.fivucsas.identity.entity.VerificationStepResult.class);
        when(pendingStep.getStatus()).thenReturn(VerificationStepStatus.PENDING);
        when(stepResultRepository.findAllBySessionIdOrderByStepNumberAsc(sessionId))
                .thenReturn(List.of(pendingStep));

        // when/then
        assertThatThrownBy(() -> service.completeSession(sessionId))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Not all steps are completed");
    }

    @Test
    void submitStepResult_WhenSessionTerminal_ShouldThrow() {
        // given
        UUID sessionId = UUID.randomUUID();
        VerificationSession session = mock(VerificationSession.class);
        when(session.isTerminal()).thenReturn(true);
        when(session.getStatus()).thenReturn(VerificationSessionStatus.COMPLETED);
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        SubmitVerificationStepCommand command = new SubmitVerificationStepCommand(
                "DOCUMENT_SCAN", 0.95, "{}", null);

        // when/then
        assertThatThrownBy(() -> service.submitStepResult(sessionId, 1, command))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("terminal state");
    }

    @Test
    void submitStepResult_WhenSessionExpired_ShouldThrow() {
        // given
        UUID sessionId = UUID.randomUUID();
        VerificationSession session = mock(VerificationSession.class);
        when(session.isTerminal()).thenReturn(false);
        when(session.isExpired()).thenReturn(true);
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        SubmitVerificationStepCommand command = new SubmitVerificationStepCommand(
                "FACE_MATCH", 0.85, "{}", null);

        // when/then
        assertThatThrownBy(() -> service.submitStepResult(sessionId, 1, command))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expired");

        verify(session).markExpired();
        verify(sessionRepository).save(session);
    }

    @Test
    void reviewStep_WhenStepNotPendingReview_ShouldThrow() {
        // given
        UUID sessionId = UUID.randomUUID();
        VerificationSession session = mock(VerificationSession.class);
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        com.fivucsas.identity.entity.VerificationStepResult stepResult = mock(com.fivucsas.identity.entity.VerificationStepResult.class);
        when(stepResult.getStatus()).thenReturn(VerificationStepStatus.COMPLETED);
        when(stepResultRepository.findBySessionIdAndStepNumber(sessionId, 1))
                .thenReturn(Optional.of(stepResult));

        // when/then
        assertThatThrownBy(() -> service.reviewStep(sessionId, 1, true, "looks good"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not in PENDING_REVIEW state");
    }

    @Test
    void reviewStep_WhenSessionNotFound_ShouldThrow() {
        // given
        UUID sessionId = UUID.randomUUID();
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.reviewStep(sessionId, 1, true, null))
                .isInstanceOf(EntityNotFoundException.class);
    }
}
