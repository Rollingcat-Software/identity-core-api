package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.SubmitVerificationStepCommand;
import com.fivucsas.identity.application.dto.response.*;
import com.fivucsas.identity.application.service.verification.VerificationStepHandlerRegistry;
import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.domain.model.auth.FlowType;
import com.fivucsas.identity.domain.model.auth.VerificationLevel;
import com.fivucsas.identity.domain.model.auth.VerificationSessionStatus;
import com.fivucsas.identity.domain.model.auth.VerificationStepStatus;
import com.fivucsas.identity.entity.*;
import com.fivucsas.identity.repository.VerificationDocumentRepository;
import com.fivucsas.identity.repository.VerificationSessionRepository;
import com.fivucsas.identity.repository.VerificationStepResultRepository;
import com.fivucsas.identity.repository.AuthFlowRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class ManageVerificationService {

    private static final List<IndustryTemplateResponse> INDUSTRY_TEMPLATES = List.of(
            new IndustryTemplateResponse(
                    "FINTECH_KYC",
                    "Fintech KYC",
                    "Full KYC pipeline for financial services",
                    List.of("DOCUMENT_SCAN", "NFC_CHIP_READ", "DATA_EXTRACT", "FACE_MATCH", "LIVENESS_CHECK", "WATCHLIST_CHECK")
            ),
            new IndustryTemplateResponse(
                    "HEALTHCARE_BASIC",
                    "Healthcare Basic",
                    "Patient identity verification for healthcare",
                    List.of("DOCUMENT_SCAN", "FACE_MATCH", "LIVENESS_CHECK")
            ),
            new IndustryTemplateResponse(
                    "EDUCATION_AGE",
                    "Education Age Verification",
                    "Age and identity verification for educational platforms",
                    List.of("DOCUMENT_SCAN", "DATA_EXTRACT", "AGE_VERIFICATION", "FACE_MATCH")
            ),
            new IndustryTemplateResponse(
                    "TELECOM_ONBOARDING",
                    "Telecom Onboarding",
                    "SIM registration and identity verification",
                    List.of("DOCUMENT_SCAN", "DATA_EXTRACT", "FACE_MATCH", "LIVENESS_CHECK", "PHONE_VERIFICATION")
            ),
            new IndustryTemplateResponse(
                    "SIMPLE_DOCUMENT",
                    "Simple Document Check",
                    "Basic document and face verification",
                    List.of("DOCUMENT_SCAN", "FACE_MATCH")
            )
    );

    private final VerificationSessionRepository sessionRepository;
    private final VerificationStepResultRepository stepResultRepository;
    private final VerificationDocumentRepository documentRepository;
    private final AuthFlowRepository authFlowRepository;
    private final UserRepository userRepository;
    private final JpaTenantRepository tenantRepository;
    private final VerificationStepHandlerRegistry handlerRegistry;
    private final ObjectMapper objectMapper;

    @Transactional
    public VerificationSessionResponse createSession(UUID userId, UUID tenantId, UUID flowId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));
        AuthFlow flow = authFlowRepository.findById(flowId)
                .orElseThrow(() -> new EntityNotFoundException("Auth flow not found: " + flowId));

        if (flow.getFlowType() != FlowType.VERIFICATION) {
            throw new IllegalArgumentException("Flow " + flowId + " is not a VERIFICATION flow");
        }

        VerificationSession session = VerificationSession.builder()
                .user(user)
                .tenant(tenant)
                .flow(flow)
                .status(VerificationSessionStatus.PENDING)
                .currentStepNumber(0)
                .expiresAt(Instant.now().plus(30, ChronoUnit.MINUTES))
                .build();

        VerificationSession saved = sessionRepository.save(session);
        log.info("Created verification session {} for user {} with flow {}", saved.getId(), userId, flowId);
        return VerificationSessionResponse.from(saved);
    }

    @Transactional
    public VerificationStepResultResponse submitStepResult(UUID sessionId, int stepNumber, SubmitVerificationStepCommand command) {
        VerificationSession session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new EntityNotFoundException("Verification session not found: " + sessionId));

        if (session.isTerminal()) {
            throw new IllegalStateException("Session " + sessionId + " is already in terminal state: " + session.getStatus());
        }

        if (session.isExpired()) {
            session.markExpired();
            sessionRepository.save(session);
            throw new IllegalStateException("Session " + sessionId + " has expired");
        }

        if (session.getStatus() == VerificationSessionStatus.PENDING) {
            session.start();
        }

        // Check if step result already exists
        VerificationStepResult stepResult = stepResultRepository
                .findBySessionIdAndStepNumber(sessionId, stepNumber)
                .orElseGet(() -> VerificationStepResult.builder()
                        .session(session)
                        .stepNumber(stepNumber)
                        .stepType(command.stepType())
                        .build());

        stepResult.markInProgress();

        // If client sent an explicit error, mark failed directly
        if (command.errorMessage() != null) {
            stepResult.markFailed(command.errorMessage());
        } else if (handlerRegistry.hasHandler(command.stepType())) {
            // Execute the registered step handler
            VerificationStepHandler handler = handlerRegistry.getHandler(command.stepType());
            Map<String, Object> inputData = parseInputData(command.resultData());
            com.fivucsas.identity.application.service.verification.VerificationStepResult handlerResult =
                    handler.execute(session, stepNumber, inputData);

            if (handlerResult.passed()) {
                String resultJson = serializeResultData(handlerResult.resultData());
                stepResult.markCompleted(handlerResult.confidence(), resultJson);
            } else if ("PENDING_REVIEW".equals(handlerResult.errorMessage())) {
                String resultJson = serializeResultData(handlerResult.resultData());
                stepResult.markPendingReview(resultJson);
            } else {
                stepResult.markFailed(handlerResult.errorMessage());
            }
        } else {
            // Fallback: no handler registered, use raw command data
            stepResult.markCompleted(command.confidence(), command.resultData());
        }

        VerificationStepResult saved = stepResultRepository.save(stepResult);

        // Advance session step counter
        if (stepNumber > session.getCurrentStepNumber()) {
            session.advanceStep();
            sessionRepository.save(session);
        }

        // Auto-complete: if current step passed, check if all flow steps are done
        if (saved.getStatus() == VerificationStepStatus.COMPLETED) {
            tryAutoCompleteSession(session);
        }

        log.info("Submitted step result for session {} step {} type {} status {}",
                sessionId, stepNumber, command.stepType(), saved.getStatus());
        return VerificationStepResultResponse.from(saved);
    }

    public VerificationSessionResponse getSession(UUID sessionId) {
        VerificationSession session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new EntityNotFoundException("Verification session not found: " + sessionId));
        return VerificationSessionResponse.from(session);
    }

    public List<IndustryTemplateResponse> getTemplates() {
        return INDUSTRY_TEMPLATES;
    }

    /**
     * Returns all VERIFICATION-type auth flows for a tenant. Used by the
     * dashboard {@code GET /api/v1/verification/flows?tenantId=…} endpoint.
     *
     * <p>Returns an empty list if the tenant has no verification flows
     * configured; never throws so the dashboard can render gracefully.</p>
     */
    public List<com.fivucsas.identity.application.dto.response.AuthFlowResponse> getVerificationFlows(UUID tenantId) {
        // tenantId == null → SUPER_ADMIN platform-wide listing.
        java.util.stream.Stream<AuthFlow> stream = tenantId == null
                ? authFlowRepository.findAll().stream()
                : authFlowRepository.findAllByTenantId(tenantId).stream();
        return stream
                .filter(f -> f.getFlowType() == FlowType.VERIFICATION)
                .map(com.fivucsas.identity.application.dto.response.AuthFlowResponse::from)
                .toList();
    }

    /**
     * Returns aggregate verification stats for a tenant, or platform-wide
     * when {@code tenantId} is {@code null}. Used by {@code GET /api/v1/verification/stats}.
     *
     * <p>Shape is a simple map rather than a dedicated DTO so the frontend
     * can render partial sections without a strict schema contract.</p>
     */
    public Map<String, Object> getVerificationStats(UUID tenantId) {
        List<VerificationSession> sessions = tenantId == null
                ? sessionRepository.findAll()
                : sessionRepository.findAllByTenantIdOrderByCreatedAtDesc(tenantId);

        long total = sessions.size();
        long completed = sessions.stream()
                .filter(s -> s.getStatus() == VerificationSessionStatus.COMPLETED).count();
        long failed = sessions.stream()
                .filter(s -> s.getStatus() == VerificationSessionStatus.FAILED).count();
        long inProgress = sessions.stream()
                .filter(s -> s.getStatus() == VerificationSessionStatus.IN_PROGRESS
                        || s.getStatus() == VerificationSessionStatus.PENDING).count();
        long expired = sessions.stream()
                .filter(s -> s.getStatus() == VerificationSessionStatus.EXPIRED).count();
        double completionRate = total == 0 ? 0.0 : ((double) completed / total) * 100.0;
        double failureRate = total == 0 ? 0.0 : ((double) failed / total) * 100.0;
        double successRate = total == 0 ? 0.0 : (double) completed / total;

        // Average time-to-complete (minutes) — only over COMPLETED sessions
        // with non-null completedAt.
        double avgTimeMinutes = sessions.stream()
                .filter(s -> s.getStatus() == VerificationSessionStatus.COMPLETED
                        && s.getCompletedAt() != null && s.getCreatedAt() != null)
                .mapToLong(s -> ChronoUnit.MINUTES.between(s.getCreatedAt(), s.getCompletedAt()))
                .average()
                .orElse(0.0);

        // Status distribution — one entry per status that actually appears.
        java.util.Map<VerificationSessionStatus, Long> statusCounts = sessions.stream()
                .collect(java.util.stream.Collectors.groupingBy(
                        VerificationSession::getStatus,
                        java.util.stream.Collectors.counting()));
        List<Map<String, Object>> statusDistribution = statusCounts.entrySet().stream()
                .map(e -> {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("status", e.getKey().name().toLowerCase(java.util.Locale.ROOT));
                    entry.put("count", e.getValue());
                    return entry;
                })
                .toList();

        // Daily verification counts — last 30 days, ISO date keys.
        Instant cutoff = Instant.now().minus(30, ChronoUnit.DAYS);
        java.util.Map<String, Long> perDay = sessions.stream()
                .filter(s -> s.getCreatedAt() != null && s.getCreatedAt().isAfter(cutoff))
                .collect(java.util.stream.Collectors.groupingBy(
                        s -> s.getCreatedAt()
                                .atZone(java.time.ZoneOffset.UTC)
                                .toLocalDate()
                                .toString(),
                        java.util.stream.Collectors.counting()));
        List<Map<String, Object>> dailyVerifications = perDay.entrySet().stream()
                .sorted(java.util.Map.Entry.comparingByKey())
                .map(e -> {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("date", e.getKey());
                    entry.put("count", e.getValue());
                    return entry;
                })
                .toList();

        // Top failure reasons — derived from failed step results when present;
        // empty list when there is nothing to report (UI renders "no data").
        List<VerificationStepResult> failedSteps = sessions.stream()
                .filter(s -> s.getStatus() == VerificationSessionStatus.FAILED)
                .flatMap(s -> stepResultRepository.findAllBySessionIdOrderByStepNumberAsc(s.getId()).stream())
                .filter(r -> r.getStatus() == VerificationStepStatus.FAILED)
                .toList();
        java.util.Map<String, Long> reasonCounts = failedSteps.stream()
                .map(r -> r.getErrorMessage() != null && !r.getErrorMessage().isBlank()
                        ? r.getErrorMessage()
                        : (r.getStepType() != null ? r.getStepType() : "unknown"))
                .collect(java.util.stream.Collectors.groupingBy(
                        r -> r, java.util.stream.Collectors.counting()));
        List<Map<String, Object>> failureReasons = reasonCounts.entrySet().stream()
                .sorted(java.util.Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .map(e -> {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("reason", e.getKey());
                    entry.put("count", e.getValue());
                    return entry;
                })
                .toList();

        Map<String, Object> stats = new HashMap<>();
        stats.put("tenantId", tenantId != null ? tenantId.toString() : null);
        stats.put("total", total);
        stats.put("totalVerifications", total);
        stats.put("completed", completed);
        stats.put("failed", failed);
        stats.put("inProgress", inProgress);
        stats.put("expired", expired);
        stats.put("successRate", successRate);
        stats.put("completionRate", completionRate);
        stats.put("failureRate", failureRate);
        stats.put("avgTimeMinutes", avgTimeMinutes);
        stats.put("statusDistribution", statusDistribution);
        stats.put("dailyVerifications", dailyVerifications);
        stats.put("failureReasons", failureReasons);
        return stats;
    }

    /**
     * Lists verification sessions for a tenant (or all tenants when
     * {@code tenantId} is {@code null}). Results are in reverse-chronological
     * order. Used by {@code GET /api/v1/verification/sessions}.
     */
    public List<VerificationSessionResponse> listSessions(UUID tenantId) {
        List<VerificationSession> sessions = tenantId == null
                ? sessionRepository.findAll()
                : sessionRepository.findAllByTenantIdOrderByCreatedAtDesc(tenantId);
        return sessions.stream()
                .map(VerificationSessionResponse::from)
                .toList();
    }

    public VerificationStatusResponse getUserVerificationStatus(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));

        List<VerificationSession> sessions = sessionRepository.findAllByUserIdOrderByCreatedAtDesc(userId);
        List<VerificationSessionResponse> sessionResponses = sessions.stream()
                .map(VerificationSessionResponse::from)
                .toList();

        return new VerificationStatusResponse(
                userId,
                user.isIdentityVerified(),
                user.getVerificationLevel(),
                user.getIdentityVerifiedAt(),
                sessionResponses
        );
    }

    @Transactional
    public VerificationSessionResponse completeSession(UUID sessionId) {
        VerificationSession session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new EntityNotFoundException("Verification session not found: " + sessionId));

        if (session.isTerminal()) {
            throw new IllegalStateException("Session " + sessionId + " is already in terminal state: " + session.getStatus());
        }

        // Check all steps are completed
        List<VerificationStepResult> results = stepResultRepository.findAllBySessionIdOrderByStepNumberAsc(sessionId);
        boolean allCompleted = results.stream()
                .allMatch(r -> r.getStatus() == VerificationStepStatus.COMPLETED || r.getStatus() == VerificationStepStatus.SKIPPED);

        boolean anyFailed = results.stream()
                .anyMatch(r -> r.getStatus() == VerificationStepStatus.FAILED);

        if (anyFailed) {
            session.markFailed();
            sessionRepository.save(session);
            log.info("Verification session {} marked as FAILED due to failed steps", sessionId);
            return VerificationSessionResponse.from(session);
        }

        if (!allCompleted) {
            throw new IllegalStateException("Not all steps are completed for session " + sessionId);
        }

        session.markCompleted();
        sessionRepository.save(session);

        // Mark user as identity verified
        User user = session.getUser();
        VerificationLevel level = determineVerificationLevel(results);
        user.markIdentityVerified(level);
        userRepository.save(user);

        log.info("Verification session {} completed. User {} marked as identity verified at level {}",
                sessionId, user.getId(), level);
        return VerificationSessionResponse.from(session);
    }

    /**
     * Admin review of a verification step (e.g., video interview).
     * Updates the step from PENDING_REVIEW to COMPLETED or FAILED.
     * If all steps pass after review, auto-completes the session.
     *
     * @param sessionId  the verification session ID
     * @param stepNumber the step number to review
     * @param approved   true to approve, false to reject
     * @param notes      optional reviewer notes
     * @return updated step result
     */
    @Transactional
    public VerificationStepResultResponse reviewStep(UUID sessionId, int stepNumber, boolean approved, String notes) {
        VerificationSession session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new EntityNotFoundException("Verification session not found: " + sessionId));

        VerificationStepResult stepResult = stepResultRepository
                .findBySessionIdAndStepNumber(sessionId, stepNumber)
                .orElseThrow(() -> new EntityNotFoundException(
                        "Step result not found for session " + sessionId + " step " + stepNumber));

        if (stepResult.getStatus() != VerificationStepStatus.PENDING_REVIEW) {
            throw new IllegalStateException(
                    "Step " + stepNumber + " is not in PENDING_REVIEW state (current: " + stepResult.getStatus() + ")");
        }

        // Build updated result data with review info
        Map<String, Object> existingData = parseInputData(stepResult.getResultData());
        existingData.put("review_approved", approved);
        existingData.put("review_notes", notes);
        existingData.put("reviewed_at", Instant.now().toString());

        if (approved) {
            stepResult.markCompleted(null, serializeResultData(existingData));
            log.info("Admin approved step {} for session {}", stepNumber, sessionId);
        } else {
            stepResult.markFailed(notes != null ? notes : "Rejected by admin");
            log.info("Admin rejected step {} for session {}: {}", stepNumber, sessionId, notes);
        }

        VerificationStepResult saved = stepResultRepository.save(stepResult);

        // Check if session can now auto-complete or should fail
        if (approved) {
            tryAutoCompleteSession(session);
        } else {
            session.markFailed();
            sessionRepository.save(session);
            log.info("Session {} marked as FAILED after admin rejection of step {}", sessionId, stepNumber);
        }

        return VerificationStepResultResponse.from(saved);
    }

    /**
     * Checks if all steps in the session's flow are completed and auto-completes the session.
     */
    private void tryAutoCompleteSession(VerificationSession session) {
        AuthFlow flow = session.getFlow();
        int totalSteps = flow.getStepCount();
        if (totalSteps == 0) return;

        List<VerificationStepResult> results =
                stepResultRepository.findAllBySessionIdOrderByStepNumberAsc(session.getId());

        long completedOrSkipped = results.stream()
                .filter(r -> r.getStatus() == VerificationStepStatus.COMPLETED
                        || r.getStatus() == VerificationStepStatus.SKIPPED)
                .count();

        boolean anyFailed = results.stream()
                .anyMatch(r -> r.getStatus() == VerificationStepStatus.FAILED);

        if (anyFailed) {
            session.markFailed();
            sessionRepository.save(session);
            log.info("Session {} auto-failed due to failed step", session.getId());
        } else if (completedOrSkipped >= totalSteps) {
            session.markCompleted();
            sessionRepository.save(session);

            User user = session.getUser();
            VerificationLevel level = determineVerificationLevel(results);
            user.markIdentityVerified(level);
            userRepository.save(user);
            log.info("Session {} auto-completed. User {} verified at level {}",
                    session.getId(), user.getId(), level);
        }
    }

    private Map<String, Object> parseInputData(String resultData) {
        if (resultData == null || resultData.isBlank()) {
            return new HashMap<>();
        }
        try {
            return objectMapper.readValue(resultData, new TypeReference<>() {});
        } catch (Exception e) {
            log.warn("Could not parse input data as JSON: {}", e.getMessage());
            Map<String, Object> map = new HashMap<>();
            map.put("raw", resultData);
            return map;
        }
    }

    private String serializeResultData(Map<String, Object> data) {
        if (data == null || data.isEmpty()) return "{}";
        try {
            return objectMapper.writeValueAsString(data);
        } catch (Exception e) {
            log.warn("Could not serialize result data: {}", e.getMessage());
            return "{}";
        }
    }

    private VerificationLevel determineVerificationLevel(List<VerificationStepResult> results) {
        long completedCount = results.stream()
                .filter(r -> r.getStatus() == VerificationStepStatus.COMPLETED)
                .count();

        if (completedCount >= 5) return VerificationLevel.FULL;
        if (completedCount >= 4) return VerificationLevel.ENHANCED;
        if (completedCount >= 3) return VerificationLevel.STANDARD;
        if (completedCount >= 1) return VerificationLevel.BASIC;
        return VerificationLevel.NONE;
    }
}
