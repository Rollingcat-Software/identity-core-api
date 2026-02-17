package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CompleteAuthStepCommand;
import com.fivucsas.identity.application.dto.command.StartAuthSessionCommand;
import com.fivucsas.identity.application.dto.response.AuthSessionResponse;
import com.fivucsas.identity.application.dto.response.StepResultResponse;
import com.fivucsas.identity.application.port.input.ExecuteAuthSessionUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.application.service.handler.AuthMethodHandler;
import com.fivucsas.identity.application.service.handler.StepResult;
import com.fivucsas.identity.domain.model.auth.*;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.*;
import com.fivucsas.identity.repository.*;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class ExecuteAuthSessionService implements ExecuteAuthSessionUseCase {

    private final AuthSessionRepository authSessionRepository;
    private final AuthSessionStepRepository authSessionStepRepository;
    private final AuthFlowRepository authFlowRepository;
    private final AuthFlowStepRepository authFlowStepRepository;
    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final AuthMethodHandlerRegistry handlerRegistry;
    private final TokenGenerationPort tokenGenerator;
    private final AuditLogPort auditLogPort;

    private static final int SESSION_TIMEOUT_MINUTES = 10;

    @Override
    public AuthSessionResponse startSession(StartAuthSessionCommand command) {
        Tenant tenant = tenantRepository.findBySlug(command.tenantSlug())
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + command.tenantSlug()));

        AuthFlow flow = authFlowRepository
                .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                        tenant.getId(), command.operationType())
                .orElseThrow(() -> new EntityNotFoundException(
                        "No default auth flow for operation: " + command.operationType()));

        User user = null;
        if (command.email() != null) {
            user = userRepository.findByEmail(command.email()).orElse(null);
        }

        AuthSession session = AuthSession.builder()
                .user(user)
                .tenant(tenant)
                .authFlow(flow)
                .operationType(command.operationType())
                .clientPlatform(command.platform())
                .clientDeviceId(command.deviceFingerprint())
                .ipAddress(command.ipAddress())
                .userAgent(command.userAgent())
                .expiresAt(Instant.now().plus(SESSION_TIMEOUT_MINUTES, ChronoUnit.MINUTES))
                .build();

        AuthSession savedSession = authSessionRepository.save(session);

        List<AuthFlowStep> flowSteps = authFlowStepRepository
                .findAllByAuthFlowIdOrderByStepOrderAsc(flow.getId());

        for (AuthFlowStep flowStep : flowSteps) {
            AuthSessionStep sessionStep = AuthSessionStep.builder()
                    .session(savedSession)
                    .authFlowStep(flowStep)
                    .methodType(flowStep.getAuthMethod().getType())
                    .build();
            authSessionStepRepository.save(sessionStep);
        }

        log.info("Auth session created: {} for tenant: {}", savedSession.getId(), tenant.getSlug());
        return AuthSessionResponse.from(authSessionRepository.findById(savedSession.getId()).orElseThrow());
    }

    @Override
    @Transactional(readOnly = true)
    public AuthSessionResponse getSessionStatus(UUID sessionId) {
        AuthSession session = authSessionRepository.findById(sessionId)
                .orElseThrow(() -> new EntityNotFoundException("Session not found: " + sessionId));
        return AuthSessionResponse.from(session);
    }

    @Override
    public StepResultResponse completeStep(UUID sessionId, int stepOrder, CompleteAuthStepCommand command) {
        AuthSession session = authSessionRepository.findByIdForUpdate(sessionId)
                .orElseThrow(() -> new EntityNotFoundException("Session not found: " + sessionId));

        if (session.isExpired()) {
            session.markExpired();
            authSessionRepository.save(session);
            throw new IllegalStateException("Session has expired");
        }

        if (session.isTerminal()) {
            throw new IllegalStateException("Session is already in terminal state: " + session.getStatus());
        }

        if (session.getStatus() == AuthSessionStatus.CREATED) {
            session.markInProgress();
        }

        List<AuthSessionStep> sessionSteps = authSessionStepRepository.findAllBySessionId(sessionId);
        AuthSessionStep currentStep = sessionSteps.stream()
                .filter(s -> s.getAuthFlowStep().getStepOrder() == stepOrder)
                .findFirst()
                .orElseThrow(() -> new EntityNotFoundException("Step not found for order: " + stepOrder));

        AuthFlowStep flowStep = currentStep.getAuthFlowStep();

        currentStep.incrementAttempts();
        if (currentStep.hasExceededMaxAttempts(flowStep.getMaxAttempts())) {
            currentStep.fail("{\"error\":\"max_attempts_exceeded\"}");
            session.markFailed();
            authSessionRepository.save(session);
            authSessionStepRepository.save(currentStep);
            return buildStepResult(currentStep, session, null);
        }

        currentStep.start();

        AuthMethodHandler handler = handlerRegistry.getHandler(currentStep.getMethodType());
        StepResult result = handler.validate(session, flowStep, command.data());

        if (result.isSuccess()) {
            currentStep.complete(result.toJson());

            if (currentStep.getMethodType() == AuthMethodType.PASSWORD && session.getUser() == null) {
                String email = (String) command.data().get("email");
                if (email != null) {
                    userRepository.findByEmail(email).ifPresent(session::assignUser);
                }
            }

            Integer nextStep = findNextRequiredStep(sessionSteps, stepOrder);
            if (nextStep == null) {
                session.markCompleted();
                authSessionRepository.save(session);
                authSessionStepRepository.save(currentStep);

                StepResultResponse.AuthenticationResult authResult = null;
                if (session.getUser() != null) {
                    String accessToken = tokenGenerator.generateAccessToken(session.getUser().getEmail());
                    authResult = new StepResultResponse.AuthenticationResult(
                            accessToken, null, 3600, session.getUser().getId());
                }
                return buildStepResult(currentStep, session, authResult);
            } else {
                session.advanceStep();
                authSessionRepository.save(session);
                authSessionStepRepository.save(currentStep);
                return new StepResultResponse(stepOrder, currentStep.getMethodType().name(),
                        currentStep.getStatus().name(), nextStep, session.getStatus(), null);
            }
        } else {
            currentStep.fail(result.toJson());
            authSessionStepRepository.save(currentStep);

            if (currentStep.hasExceededMaxAttempts(flowStep.getMaxAttempts())) {
                session.markFailed();
                authSessionRepository.save(session);
            }

            return buildStepResult(currentStep, session, null);
        }
    }

    @Override
    public StepResultResponse skipStep(UUID sessionId, int stepOrder) {
        AuthSession session = authSessionRepository.findByIdForUpdate(sessionId)
                .orElseThrow(() -> new EntityNotFoundException("Session not found: " + sessionId));

        List<AuthSessionStep> sessionSteps = authSessionStepRepository.findAllBySessionId(sessionId);
        AuthSessionStep currentStep = sessionSteps.stream()
                .filter(s -> s.getAuthFlowStep().getStepOrder() == stepOrder)
                .findFirst()
                .orElseThrow(() -> new EntityNotFoundException("Step not found for order: " + stepOrder));

        if (currentStep.getAuthFlowStep().isRequired()) {
            throw new IllegalStateException("Cannot skip required step");
        }

        currentStep.skip();
        authSessionStepRepository.save(currentStep);

        Integer nextStep = findNextRequiredStep(sessionSteps, stepOrder);
        if (nextStep == null) {
            session.markCompleted();
        } else {
            session.advanceStep();
        }
        authSessionRepository.save(session);

        return new StepResultResponse(stepOrder, currentStep.getMethodType().name(),
                "SKIPPED", nextStep, session.getStatus(), null);
    }

    @Override
    public void cancelSession(UUID sessionId) {
        AuthSession session = authSessionRepository.findByIdForUpdate(sessionId)
                .orElseThrow(() -> new EntityNotFoundException("Session not found: " + sessionId));
        session.cancel();
        authSessionRepository.save(session);
        log.info("Auth session cancelled: {}", sessionId);
    }

    private Integer findNextRequiredStep(List<AuthSessionStep> steps, int currentOrder) {
        return steps.stream()
                .filter(s -> s.getAuthFlowStep().getStepOrder() > currentOrder)
                .filter(s -> s.getStatus() == AuthStepStatus.PENDING || s.getStatus() == AuthStepStatus.IN_PROGRESS)
                .map(s -> s.getAuthFlowStep().getStepOrder())
                .findFirst()
                .orElse(null);
    }

    private StepResultResponse buildStepResult(AuthSessionStep step, AuthSession session,
                                                StepResultResponse.AuthenticationResult authResult) {
        return new StepResultResponse(
                step.getAuthFlowStep().getStepOrder(),
                step.getMethodType().name(),
                step.getStatus().name(),
                null,
                session.getStatus(),
                authResult
        );
    }
}
