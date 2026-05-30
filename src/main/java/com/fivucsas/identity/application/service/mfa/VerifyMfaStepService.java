package com.fivucsas.identity.application.service.mfa;

import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.application.service.EnrollmentHealthService;
import com.fivucsas.identity.domain.exception.OtpAttemptsExhaustedException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.dto.AvailableMfaMethod;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Orchestrator for {@code POST /auth/mfa/step}.
 *
 * <p>Extracted from {@code AuthController.verifyMfaStep} as part of the
 * P2.9 refactor. The controller now collapses to argument parsing + HTTP
 * response shaping; all business logic — session lookup, dispatch to the
 * per-method strategy, audit logging, RFC 8176 {@code amr} accumulation,
 * and final-step JWT minting — lives here.
 *
 * <p>Cross-cutting concerns intentionally kept here (NOT pushed into
 * {@link VerifyMfaStepHandler} implementations):
 * <ul>
 *   <li>Pessimistic-lock on the MFA session row (closes 2026-04-28 P0 #1
 *       race where parallel correct OTPs would double-credit the step).</li>
 *   <li>Same-method substitution guard (METHOD_ALREADY_USED) — must compare
 *       against the current step's configured methods, NOT just blindly
 *       reject any reuse.</li>
 *   <li>Audit log emissions for STEP_COMPLETED, STEP_FAILED, MFA_COMPLETE.</li>
 *   <li>JWT + refresh token minting on final step.</li>
 * </ul>
 */
@Service
@Slf4j
public class VerifyMfaStepService {

    /** RFC 8176 Authentication Methods References mapping. */
    private static final Map<AuthMethodType, String> AMR_VALUES;
    static {
        Map<AuthMethodType, String> m = new EnumMap<>(AuthMethodType.class);
        m.put(AuthMethodType.PASSWORD, "pwd");
        m.put(AuthMethodType.EMAIL_OTP, "otp");
        m.put(AuthMethodType.SMS_OTP, "sms");
        m.put(AuthMethodType.TOTP, "otp");
        m.put(AuthMethodType.FACE, "face");
        m.put(AuthMethodType.VOICE, "voice");
        m.put(AuthMethodType.FINGERPRINT, "fpt");
        m.put(AuthMethodType.HARDWARE_KEY, "hwk");
        // PASSKEY is the discoverable mode of WebAuthn → same "hwk" amr (task #16 G).
        m.put(AuthMethodType.PASSKEY, "hwk");
        m.put(AuthMethodType.QR_CODE, "mca");
        // APPROVE_LOGIN is the number-matching mode of the QR cross-device
        // approval method → same "mca" multi-channel-authentication amr.
        m.put(AuthMethodType.APPROVE_LOGIN, "mca");
        m.put(AuthMethodType.NFC_DOCUMENT, "swk");
        AMR_VALUES = Collections.unmodifiableMap(m);
    }

    private final Map<AuthMethodType, VerifyMfaStepHandler> handlers;
    private final MfaSessionRepository mfaSessionRepository;
    private final UserRepository userRepository;
    private final AuthFlowRepositoryPort authFlowRepository;
    private final EnrollmentHealthService enrollmentHealthService;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogPort auditLogPort;

    public VerifyMfaStepService(
            List<VerifyMfaStepHandler> handlerBeans,
            MfaSessionRepository mfaSessionRepository,
            UserRepository userRepository,
            AuthFlowRepositoryPort authFlowRepository,
            EnrollmentHealthService enrollmentHealthService,
            TokenGenerationPort tokenGenerator,
            RefreshTokenService refreshTokenService,
            AuditLogPort auditLogPort) {
        Map<AuthMethodType, VerifyMfaStepHandler> map = new EnumMap<>(AuthMethodType.class);
        for (VerifyMfaStepHandler h : handlerBeans) {
            VerifyMfaStepHandler prior = map.put(h.supports(), h);
            if (prior != null) {
                throw new IllegalStateException(
                        "Duplicate VerifyMfaStepHandler for " + h.supports()
                                + ": " + prior.getClass() + " and " + h.getClass());
            }
        }
        this.handlers = Collections.unmodifiableMap(map);
        this.mfaSessionRepository = mfaSessionRepository;
        this.userRepository = userRepository;
        this.authFlowRepository = authFlowRepository;
        this.enrollmentHealthService = enrollmentHealthService;
        this.tokenGenerator = tokenGenerator;
        this.refreshTokenService = refreshTokenService;
        this.auditLogPort = auditLogPort;
    }

    /**
     * Execute one MFA step verification.
     *
     * <p>Caller (controller) owns rate limiting and request-context details
     * (IP / User-Agent), passing them in via {@link VerifyMfaStepRequest}.
     * The returned {@link VerifyMfaStepResponse} is rendered to JSON by the
     * controller — this service does NOT produce {@link
     * org.springframework.http.ResponseEntity} so it stays HTTP-agnostic.
     */
    @Transactional
    public VerifyMfaStepResponse execute(VerifyMfaStepRequest req) {
        if (req.sessionToken() == null || req.sessionToken().isBlank()) {
            return VerifyMfaStepResponse.badRequest("sessionToken is required");
        }
        if (req.method() == null || req.method().isBlank()) {
            return VerifyMfaStepResponse.badRequest("method is required");
        }

        // Pessimistic-lock the MFA session row for the duration of this step.
        // Without it, two parallel correct OTP submissions in the same window
        // would both pass the read → validate → save block and double-credit
        // completedMethods, advancing currentStep twice in one race. Closes
        // audit-edge 2026-04-28 P0 #1.
        Optional<MfaSession> sessionOpt = mfaSessionRepository
                .findBySessionTokenForUpdate(req.sessionToken());
        if (sessionOpt.isEmpty()) {
            return VerifyMfaStepResponse.unauthorized("Invalid or expired MFA session");
        }
        MfaSession session = sessionOpt.get();
        if (session.isExpired()) {
            mfaSessionRepository.delete(session);
            return VerifyMfaStepResponse.unauthorized("MFA session expired. Please login again.");
        }
        if (session.isCompleted()) {
            return VerifyMfaStepResponse.badRequest("MFA session already completed");
        }

        User user = userRepository.findById(session.getUserId())
                .orElseThrow(() -> new UserNotFoundException("User not found for MFA session"));

        AuthMethodType methodType;
        try {
            methodType = AuthMethodType.valueOf(req.method());
        } catch (IllegalArgumentException e) {
            return VerifyMfaStepResponse.badRequest("Unknown auth method: " + req.method());
        }

        VerifyMfaStepHandler handler = handlers.get(methodType);
        if (handler == null) {
            return VerifyMfaStepResponse.badRequest("No handler registered for: " + methodType);
        }

        Map<String, Object> data = req.data() != null ? req.data() : Map.of();

        // WebAuthn two-phase flow: a request with action=challenge produces a
        // server challenge that the browser feeds to navigator.credentials.get
        // — it does not VERIFY anything yet. The original
        // AuthController.verifyMfaStep short-circuited the substitution guard
        // for this case so a re-request after a temporary failure would still
        // mint a new challenge. Mirror that behavior: call the handler before
        // the same-method guard. The handler MUST return a CHALLENGE result
        // when action=challenge; anything else (valid, invalid, throw) is a
        // contract violation that we surface as 400 BAD_REQUEST, NOT by
        // re-invoking the handler in the normal path (which would
        // double-process counters / attempt tracking).
        boolean isChallengeRequest = "challenge".equals(data.get("action"));
        if (isChallengeRequest) {
            try {
                MfaStepResult challengeResult = handler.verify(session, user, data);
                if (challengeResult.isChallenge()) {
                    return VerifyMfaStepResponse.passthrough(challengeResult.challengeResponse());
                }
                // Handler returned a non-challenge result for action=challenge.
                // This is a contract violation — surface as 400 instead of
                // calling the handler a second time on the verification path.
                log.warn("AUDIT: MFA challenge handler returned non-challenge result — method: {}, userId={}",
                        req.method(), session.getUserId());
                auditLogPort.logMfaStepFailed(session.getUserId().toString(), req.method(),
                        "challenge-handler-contract-violation", req.clientIp(), req.userAgent());
                return VerifyMfaStepResponse.badRequest(
                        "Challenge action is not supported for method " + req.method());
            } catch (OtpAttemptsExhaustedException e) {
                // OTP attempt budget exhausted — surface as 429 via
                // GlobalExceptionHandler (with Retry-After); never swallow into
                // a generic 200 ERROR. Re-throw to honour the rate-limit contract.
                throw e;
            } catch (RuntimeException e) {
                // Handler signature is `verify(...) throws nothing` — only
                // RuntimeExceptions can escape. We re-set the interrupt flag
                // if the cause chain contains an InterruptedException (e.g.
                // an HTTP client wrapping InterruptedException in
                // RuntimeException) so cooperative cancellation isn't lost.
                if (containsInterrupted(e)) {
                    Thread.currentThread().interrupt();
                }
                // Detailed message goes to the server log + audit row only —
                // never the client (could leak upstream IDs / config / stack
                // context). User sees a stable, non-leaking message.
                log.error("AUDIT: MFA challenge error — method: {}, userId={}, ip={}, userAgent={}",
                        req.method(), session.getUserId(),
                        req.clientIp(), req.userAgent(), e);
                auditLogPort.logMfaStepFailed(session.getUserId().toString(), req.method(),
                        "challenge-error: " + e.getClass().getSimpleName(),
                        req.clientIp(), req.userAgent());
                return VerifyMfaStepResponse.error("Challenge could not be created");
            }
        }

        // Same-method prevention (substitution guard, NOT a retry guard). See
        // detailed rationale in original AuthController.verifyMfaStep — only
        // reject when the method was previously completed AND is NOT the
        // current step's expected method. Compare by AuthMethodType.name() so
        // EMAIL_OTP and TOTP (which share AMR "otp") are treated as distinct.
        String reuseKey = methodType.name();
        List<String> completedMethods = session.getCompletedMethods();
        Set<String> currentStepMethodNames = resolveCurrentStepMethodNames(session);
        boolean submittedMethodIsExpectedAtCurrentStep = currentStepMethodNames.contains(reuseKey);
        if (completedMethods.contains(reuseKey) && !submittedMethodIsExpectedAtCurrentStep) {
            log.warn("AUDIT: MFA same-method reuse attempt — method: {}, userId={}, ip={}, userAgent={}",
                    req.method(), user.getId(), req.clientIp(), req.userAgent());
            return VerifyMfaStepResponse.methodAlreadyUsed(
                    session.getCurrentStep(),
                    session.getTotalSteps(),
                    currentStepMethodNames,
                    completedMethods);
        }

        // Per-method verification — handler may also short-circuit with a
        // CHALLENGE response (WebAuthn two-phase flow).
        MfaStepResult result;
        try {
            result = handler.verify(session, user, data);
        } catch (OtpAttemptsExhaustedException e) {
            // OTP attempt budget exhausted — surface as 429 via
            // GlobalExceptionHandler (with Retry-After); never swallow into a
            // generic 200 ERROR. Re-throw to honour the rate-limit contract.
            throw e;
        } catch (RuntimeException e) {
            if (containsInterrupted(e)) {
                Thread.currentThread().interrupt();
            }
            // Detailed message in server log + audit only — never to the
            // client. User sees a stable non-leaking message.
            log.error("AUDIT: MFA step error — method: {}, userId={}, ip={}, userAgent={}",
                    req.method(), session.getUserId(),
                    req.clientIp(), req.userAgent(), e);
            auditLogPort.logMfaStepFailed(session.getUserId().toString(), req.method(),
                    "error: " + e.getClass().getSimpleName(),
                    req.clientIp(), req.userAgent());
            return VerifyMfaStepResponse.error("Verification could not be completed");
        }

        if (result.isChallenge()) {
            return VerifyMfaStepResponse.passthrough(result.challengeResponse());
        }

        if (!result.valid()) {
            String reason = resolveFailureReason(methodType, data);
            log.warn("AUDIT: MFA step failed — method: {}, reason: {}, userId={}, step: {}/{}, ip={}, userAgent={}",
                    req.method(), reason, user.getId(), session.getCurrentStep(),
                    session.getTotalSteps(), req.clientIp(), req.userAgent());
            auditLogPort.logMfaStepFailed(user.getId().toString(), req.method(), reason,
                    req.clientIp(), req.userAgent());
            // Edge case #5: include currentStep + expectedMethod + completedMethods so
            // clients can render "retry or switch method" UX without a separate GET.
            return VerifyMfaStepResponse.failed(
                    "Verification failed for " + req.method(),
                    session.getCurrentStep(),
                    session.getTotalSteps(),
                    req.method(),
                    completedMethods);
        }

        // Step verified — advance session.
        session.addCompletedMethod(reuseKey);
        session.advanceStep();

        // Wrap the post-verification orchestration so a flow-lookup failure or
        // token-mint failure returns a structured ERROR + audit emission
        // instead of a 500. The legacy AuthController had a try/catch on the
        // entire body for this reason; the refactor must preserve it.
        try {
            if (session.allStepsCompleted()) {
                return completeMfa(session, user, req);
            }
            return advanceToNextStep(session, user, req);
        } catch (RuntimeException e) {
            if (containsInterrupted(e)) {
                Thread.currentThread().interrupt();
            }
            // Detailed message in server log + audit only.
            log.error("AUDIT: MFA orchestration error — method: {}, userId={}, ip={}, userAgent={}",
                    req.method(), user.getId(),
                    req.clientIp(), req.userAgent(), e);
            auditLogPort.logMfaStepFailed(user.getId().toString(), req.method(),
                    "orchestration-error: " + e.getClass().getSimpleName(),
                    req.clientIp(), req.userAgent());
            return VerifyMfaStepResponse.error("MFA could not be completed");
        }
    }

    /**
     * Walks the cause chain of {@code t} looking for an
     * {@link InterruptedException}. Used to re-set the thread interrupt flag
     * when an HTTP client / executor wrapped {@code InterruptedException} as
     * a {@link RuntimeException} so cooperative cancellation isn't lost.
     */
    private static boolean containsInterrupted(Throwable t) {
        while (t != null) {
            if (t instanceof InterruptedException) {
                return true;
            }
            t = t.getCause();
        }
        return false;
    }

    private VerifyMfaStepResponse completeMfa(MfaSession session, User user, VerifyMfaStepRequest req) {
        session.complete();
        mfaSessionRepository.save(session);

        List<String> amr = session.getCompletedMethods().stream()
                .map(m -> {
                    try {
                        return AMR_VALUES.getOrDefault(AuthMethodType.valueOf(m), m.toLowerCase());
                    } catch (IllegalArgumentException e) {
                        return m.toLowerCase();
                    }
                })
                .distinct()
                .toList();

        String accessToken = tokenGenerator.generateAccessToken(user.getEmail(), amr);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
                user, session.getIpAddress(), session.getUserAgent());

        log.info("AUDIT: MFA complete — methods: {}, userId={}, ip={}, userAgent={}",
                amr, user.getId(), req.clientIp(), req.userAgent());
        auditLogPort.logMfaComplete(user.getId().toString(), amr, req.clientIp(), req.userAgent());

        UserResponse userResponse =
                com.fivucsas.identity.application.mapper.UserResponseMapper.toResponse(user);

        Map<String, Object> body = new HashMap<>();
        body.put("status", "AUTHENTICATED");
        body.put("accessToken", accessToken);
        body.put("refreshToken", refreshToken.getToken());
        body.put("expiresIn", tokenGenerator.getExpirationMillis());
        body.put("user", userResponse);
        return VerifyMfaStepResponse.passthrough(body);
    }

    private VerifyMfaStepResponse advanceToNextStep(MfaSession session, User user, VerifyMfaStepRequest req) {
        mfaSessionRepository.save(session);

        AuthFlow flow = authFlowRepository.findById(session.getFlowId())
                .orElseThrow(() -> new RuntimeException("Auth flow not found"));
        int nextStepOrder = session.getCurrentStep();
        AuthFlowStep nextStep = flow.getSteps().stream()
                .filter(s -> s.getStepOrder() == nextStepOrder)
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "Step " + nextStepOrder + " not found in flow"));

        // Exclude methods already completed earlier in this MFA session so the
        // next step never re-offers a just-completed method (e.g. FINGERPRINT
        // appearing in both step-2 and step-3 CHOICE lists).
        Set<String> completedSoFar = new HashSet<>(session.getCompletedMethods());
        List<AvailableMfaMethod> availableMethods =
                buildMfaAvailableMethods(nextStep, user, completedSoFar);
        AuthMethodType nextPrimary = nextStep.getAvailableMethods().stream()
                .filter(Objects::nonNull)
                .map(AuthMethod::getType)
                .filter(t -> !completedSoFar.contains(t.name()))
                .findFirst()
                .orElse(null);
        List<AvailableMfaMethod> alternativeMethods = nextPrimary == null
                ? List.of()
                : computeAlternativeMethods(availableMethods, nextPrimary);

        log.info("AUDIT: MFA step completed — method: {}, step: {}/{}, userId={}, ip={}, userAgent={}",
                req.method(), nextStepOrder - 1, session.getTotalSteps(), user.getId(),
                req.clientIp(), req.userAgent());
        auditLogPort.logMfaStepCompleted(user.getId().toString(), req.method(),
                nextStepOrder - 1, session.getTotalSteps(), req.clientIp(), req.userAgent());

        Map<String, Object> body = new HashMap<>();
        body.put("status", "STEP_COMPLETED");
        body.put("mfaSessionToken", req.sessionToken());
        body.put("currentStep", nextStepOrder);
        body.put("totalSteps", session.getTotalSteps());
        body.put("availableMethods", availableMethods);
        body.put("alternativeMethods", alternativeMethods);
        body.put("completedMethods", session.getCompletedMethods());
        return VerifyMfaStepResponse.passthrough(body);
    }

    private Set<String> resolveCurrentStepMethodNames(MfaSession session) {
        try {
            AuthFlow currentFlow = authFlowRepository.findById(session.getFlowId()).orElse(null);
            if (currentFlow == null) return Collections.emptySet();
            int currentStepOrder = session.getCurrentStep();
            AuthFlowStep currentStep = currentFlow.getSteps().stream()
                    .filter(s -> s.getStepOrder() == currentStepOrder)
                    .findFirst()
                    .orElse(null);
            if (currentStep == null) return Collections.emptySet();
            return currentStep.getAvailableMethods().stream()
                    .filter(Objects::nonNull)
                    .map(m -> m.getType().name())
                    .collect(java.util.stream.Collectors.toSet());
        } catch (Exception e) {
            log.warn("Failed to resolve current MFA step for reuse check (sessionId={}): {}",
                    session.getId(), e.getMessage());
            return Collections.emptySet();
        }
    }

    private List<AvailableMfaMethod> buildMfaAvailableMethods(
            AuthFlowStep step, User user, Set<String> alreadyCompleted) {
        List<AuthMethod> methods = step.getAvailableMethods();
        Map<AuthMethodType, Boolean> healthStatus =
                enrollmentHealthService.validateEnrollments(user.getId());
        String preferred = user.getPreferred2faMethod();
        return methods.stream()
                .filter(Objects::nonNull)
                .filter(m -> !alreadyCompleted.contains(m.getType().name()))
                .map(m -> AvailableMfaMethod.builder()
                        .methodType(m.getType().name())
                        .name(m.getName())
                        .category(m.getCategory().name())
                        .enrolled(Boolean.TRUE.equals(healthStatus.get(m.getType()))
                                || !m.isRequiresEnrollment())
                        .preferred(m.getType().name().equals(preferred))
                        .requiresEnrollment(m.isRequiresEnrollment())
                        .build())
                .collect(java.util.stream.Collectors.toList());
    }

    private List<AvailableMfaMethod> computeAlternativeMethods(
            List<AvailableMfaMethod> available, AuthMethodType primary) {
        if (available == null || available.isEmpty()) return List.of();
        return available.stream()
                .filter(m -> !m.getMethodType().equals(primary.name()))
                .collect(java.util.stream.Collectors.toList());
    }

    /**
     * Resolves a human-readable failure reason for audit logging. Mirrors the
     * original {@code AuthController.resolveFailureReason}.
     */
    private String resolveFailureReason(AuthMethodType methodType, Map<String, Object> data) {
        return switch (methodType) {
            case PASSWORD -> "invalid_password";
            case EMAIL_OTP, SMS_OTP -> {
                String code = data != null ? (String) data.get("code") : null;
                yield (code == null || code.isBlank()) ? "missing_otp_code" : "invalid_or_expired_otp";
            }
            case TOTP -> {
                String code = data != null ? (String) data.get("code") : null;
                yield (code == null || code.isBlank()) ? "missing_totp_code" : "invalid_totp_code";
            }
            case FACE -> {
                String image = data != null ? (String) data.get("image") : null;
                yield (image == null || image.isBlank()) ? "missing_face_image" : "face_verification_failed";
            }
            case VOICE -> {
                String voiceData = data != null ? (String) data.get("voiceData") : null;
                yield (voiceData == null || voiceData.isBlank()) ? "missing_voice_data" : "voice_verification_failed";
            }
            case FINGERPRINT, HARDWARE_KEY -> {
                String assertion = data != null ? (String) data.get("assertion") : null;
                yield (assertion == null || assertion.isBlank()) ? "missing_webauthn_assertion" : "webauthn_verification_failed";
            }
            case QR_CODE -> {
                String token = data != null ? (String) data.get("token") : null;
                yield (token == null || token.isBlank()) ? "missing_qr_token" : "invalid_qr_token";
            }
            case NFC_DOCUMENT -> {
                String nfcData = data != null ? (String) data.get("nfcData") : null;
                yield (nfcData == null || nfcData.isBlank()) ? "missing_nfc_data" : "nfc_card_not_found_or_not_owned";
            }
            default -> "verification_failed";
        };
    }

    /** Visible-for-test: how many handlers are registered (must equal AuthMethodType count covered). */
    int registeredHandlerCount() {
        return handlers.size();
    }
}
