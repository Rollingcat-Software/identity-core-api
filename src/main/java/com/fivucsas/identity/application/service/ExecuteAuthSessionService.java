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
import com.fivucsas.identity.domain.exception.NeedsEnrollmentException;
import com.fivucsas.identity.domain.model.auth.*;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthFlowStepRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthSessionRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthSessionStepRepositoryPort;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.*;
import com.fivucsas.identity.exception.DomainStateConflictException;
import com.fivucsas.identity.service.RefreshTokenService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class ExecuteAuthSessionService implements ExecuteAuthSessionUseCase {

    private final AuthSessionRepositoryPort authSessionRepository;
    private final AuthSessionStepRepositoryPort authSessionStepRepository;
    private final AuthFlowRepositoryPort authFlowRepository;
    private final AuthFlowStepRepositoryPort authFlowStepRepository;
    private final JpaTenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final AuthMethodHandlerRegistry handlerRegistry;
    private final TokenGenerationPort tokenGenerator;
    private final AuditLogPort auditLogPort;
    private final RefreshTokenService refreshTokenService;
    private final EnrollmentHealthService enrollmentHealthService;

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

        validateFlowIntegrity(flow);

        List<AuthFlowStep> flowSteps = authFlowStepRepository
                .findAllByAuthFlowIdOrderByStepOrderAsc(flow.getId());

        // Pre-flight enrollment check (post-audit 2026-04-24 login edge cases
        // #1 + #6). When the email resolves to a known user, ensure every
        // REQUIRED step has at least one usable method — otherwise the session
        // would advance past step 0 only to trap the user on an un-enrollable
        // step. Anonymous starts (no email) cannot be pre-checked here; the
        // existing per-step NEEDS_ENROLLMENT path in
        // AuthController.switchMethod covers them after PASSWORD assigns user.
        if (user != null) {
            verifyUserCanCompleteFlow(user, flowSteps);
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
            throw new DomainStateConflictException("Session has expired");
        }

        if (session.isTerminal()) {
            throw new DomainStateConflictException("Session is already in terminal state: " + session.getStatus());
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
                    RefreshToken refreshToken = refreshTokenService.createRefreshToken(
                            session.getUser(), session.getIpAddress(), session.getUserAgent());
                    authResult = new StepResultResponse.AuthenticationResult(
                            accessToken, refreshToken.getToken(),
                            tokenGenerator.getExpirationMillis() / 1000, session.getUser().getId());
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
            throw new DomainStateConflictException("Cannot skip required step");
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

    @Override
    public boolean tryCancelSession(UUID sessionId) {
        // Idempotent variant for DELETE /api/v1/auth/sessions/{sessionId}
        // (post-audit 2026-04-24 login edge case #3). Sessions already in a
        // terminal state are NOT re-transitioned — we just no-op so the second
        // DELETE call after a successful first one still returns 204.
        Optional<AuthSession> sessionOpt = authSessionRepository.findByIdForUpdate(sessionId);
        if (sessionOpt.isEmpty()) {
            return false;
        }
        AuthSession session = sessionOpt.get();
        if (session.isTerminal()) {
            log.debug("Auth session {} already terminal ({}); DELETE is a no-op",
                    sessionId, session.getStatus());
            return true;
        }
        session.cancel();
        authSessionRepository.save(session);
        log.info("Auth session cancelled via DELETE: {}", sessionId);
        return true;
    }

    /**
     * Pre-flight enrollment check — for each REQUIRED step in the flow, ensure
     * the user is enrolled in at least one of the step's available methods (or
     * the step's configured fallback). Throws {@link NeedsEnrollmentException}
     * on the first dead-end.
     *
     * <p>Mirrors {@code AuthenticateUserService.verifyUserCanCompleteFlow}; the
     * shared {@link EnrollmentHealthService} performs backing-data validation
     * so a stale ENROLLED row that no longer has crypto material is treated as
     * not-enrolled.
     */
    private void verifyUserCanCompleteFlow(User user, List<AuthFlowStep> flowSteps) {
        Map<AuthMethodType, Boolean> healthStatus =
                enrollmentHealthService.validateEnrollments(user.getId());

        for (AuthFlowStep step : flowSteps) {
            if (!step.isRequired()) {
                continue;
            }

            boolean hasEnrolledMethod = step.getAvailableMethods().stream()
                    .filter(Objects::nonNull)
                    .anyMatch(m -> isMethodUsable(m, healthStatus));
            if (hasEnrolledMethod) {
                continue;
            }

            AuthMethod fallback = step.getFallbackMethod();
            if (fallback != null && isMethodUsable(fallback, healthStatus)) {
                continue;
            }

            AuthMethodType missing = step.getAvailableMethods().stream()
                    .filter(Objects::nonNull)
                    .map(AuthMethod::getType)
                    .findFirst()
                    .orElse(fallback != null ? fallback.getType() : null);

            String methodName = missing != null ? missing.name() : "UNKNOWN";
            String enrollmentUrl = missing != null
                    ? "/enroll/" + missing.name().toLowerCase(java.util.Locale.ROOT)
                    : "/enroll";
            log.warn("AUDIT: Auth session pre-flight blocked — user {} cannot complete flow (needs {})",
                    user.getId(), methodName);
            throw new NeedsEnrollmentException(methodName, enrollmentUrl);
        }
    }

    private boolean isMethodUsable(AuthMethod method, Map<AuthMethodType, Boolean> healthStatus) {
        if (method == null) return false;
        if (!method.isRequiresEnrollment()) return true;
        return Boolean.TRUE.equals(healthStatus.get(method.getType()));
    }

    private Integer findNextRequiredStep(List<AuthSessionStep> steps, int currentOrder) {
        return steps.stream()
                .filter(s -> s.getAuthFlowStep().getStepOrder() > currentOrder)
                .filter(s -> s.getStatus() == AuthStepStatus.PENDING || s.getStatus() == AuthStepStatus.IN_PROGRESS)
                .map(s -> s.getAuthFlowStep().getStepOrder())
                .findFirst()
                .orElse(null);
    }

    /**
     * Structural integrity check for a configured {@link AuthFlow}.
     *
     * <p>Tenants are free to pick ANY {@link AuthMethodType} as step[0] — the
     * product premise is a customizable flow. This method therefore only
     * enforces that the flow is well-formed:
     *
     * <ul>
     *   <li>has at least one step;
     *   <li>step[0] (lowest stepOrder) references a non-null, persisted
     *       {@link AuthMethod}.
     * </ul>
     *
     * Step-order uniqueness and valid method references for the REMAINING
     * steps are enforced at write time by {@link ManageAuthFlowService} and
     * by DB constraints (V16 + V30 {@code chk_step_order}).
     */
    private void validateFlowIntegrity(AuthFlow flow) {
        List<AuthFlowStep> steps = authFlowStepRepository
                .findAllByAuthFlowIdOrderByStepOrderAsc(flow.getId());
        if (steps.isEmpty()) {
            throw new DomainStateConflictException("Auth flow has no steps configured");
        }
        AuthFlowStep firstStep = steps.getFirst();
        if (firstStep.getAuthMethod() == null || firstStep.getAuthMethod().getType() == null) {
            throw new IllegalStateException(
                    "First step of auth flow " + flow.getId() + " has no valid AuthMethod");
        }
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
