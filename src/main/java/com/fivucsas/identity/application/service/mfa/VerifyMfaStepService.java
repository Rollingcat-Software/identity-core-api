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
import java.util.EnumSet;
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

    /**
     * Sliding TTL granted on each SUCCESSFUL step. A multi-step flow (esp. one
     * with a FACE step) can outrun the base TTL the session was created with,
     * producing "MFA session expired" 401s mid-flow. After a step verifies we
     * push {@code expiresAt} forward by this much — but never past
     * {@link #MFA_SESSION_MAX_TTL} from creation, so a stalled/abandoned session
     * still expires on a bounded clock (no indefinite extension).
     */
    private static final java.time.Duration MFA_SESSION_STEP_EXTENSION =
            java.time.Duration.ofMinutes(10);

    /**
     * Absolute ceiling for a single MFA session, measured from {@code createdAt}.
     * The sliding extension can never push {@code expiresAt} beyond this.
     */
    private static final java.time.Duration MFA_SESSION_MAX_TTL =
            java.time.Duration.ofMinutes(30);

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
    private final AvailableMethodsResolver availableMethodsResolver;
    private final com.fivucsas.identity.application.service.TenantAuthMethodPolicy tenantAuthMethodPolicy;
    private final com.fivucsas.identity.application.service.LoginAccountStateGuard loginAccountStateGuard;
    // #15 — best-effort login-device upsert on MFA completion (the input port).
    private final com.fivucsas.identity.application.port.input.ManageDeviceUseCase manageDeviceUseCase;

    public VerifyMfaStepService(
            List<VerifyMfaStepHandler> handlerBeans,
            MfaSessionRepository mfaSessionRepository,
            UserRepository userRepository,
            AuthFlowRepositoryPort authFlowRepository,
            EnrollmentHealthService enrollmentHealthService,
            TokenGenerationPort tokenGenerator,
            RefreshTokenService refreshTokenService,
            AuditLogPort auditLogPort,
            AvailableMethodsResolver availableMethodsResolver,
            com.fivucsas.identity.application.service.TenantAuthMethodPolicy tenantAuthMethodPolicy,
            com.fivucsas.identity.application.service.LoginAccountStateGuard loginAccountStateGuard,
            com.fivucsas.identity.application.port.input.ManageDeviceUseCase manageDeviceUseCase) {
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
        this.availableMethodsResolver = availableMethodsResolver;
        this.tenantAuthMethodPolicy = tenantAuthMethodPolicy;
        this.loginAccountStateGuard = loginAccountStateGuard;
        this.manageDeviceUseCase = manageDeviceUseCase;
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

        // SECURITY (2026-06-01, LOGIC_AUDIT): enforce per-account lockout + account
        // status on the LIVE config-driven /auth/mfa/step path. Previously ONLY the
        // legacy /auth/login path checked these, so online guessing here never tripped
        // the 5-strike lock and SUSPENDED/INACTIVE users could still complete MFA.
        // Throws 423 (locked) / 403 (not active) before any factor is verified.
        loginAccountStateGuard.enforceLoginAllowed(user, user.getEmail(), req.clientIp());

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

        // ENFORCEMENT CHOKEPOINT (single place): reject a step whose method is
        // EXPLICITLY disabled for the tenant (a tenant_auth_methods row with
        // is_enabled=false). Fail-closed for THIS method only — other enabled
        // methods on the same CHOICE step still work. SAFE semantics: no row =
        // allowed, so a tenant that never configured its toggles is never
        // locked out. Runs AFTER session/handler resolution (so we know the
        // tenant + method) and BEFORE any verification side-effect (counters,
        // challenges) so a disabled method can never advance the flow.
        if (!tenantAuthMethodPolicy.isLoginMethodAllowedForTenant(session.getTenantId(), methodType)) {
            log.warn("AUDIT: MFA step rejected — method {} is disabled for tenantId={}, userId={}, ip={}",
                    methodType, session.getTenantId(), session.getUserId(), req.clientIp());
            auditLogPort.logMfaStepFailed(session.getUserId().toString(), req.method(),
                    "auth_method_disabled_for_tenant", req.clientIp(), req.userAgent());
            throw new com.fivucsas.identity.domain.exception.AuthMethodDisabledException(methodType.name());
        }

        // SECURITY (P1-1): bind the submitted method to the CURRENT step. The
        // submitted method MUST be one of the current step's permitted methods
        // (its available set + configured fallback) — exactly the rule
        // /auth/mfa/switch-method enforces. Without this a caller could answer
        // any step with any registered method (e.g. submit TOTP to satisfy a
        // FACE step). CHOICE steps stay "any-one-of" because getAvailableMethods()
        // returns the full alternatives list. Runs BEFORE the challenge
        // short-circuit and handler dispatch, so a non-permitted method never
        // triggers a verification side-effect (challenge mint, counter bump).
        //
        // A method that was already completed earlier AND is not permitted here
        // is left to the more specific METHOD_ALREADY_USED substitution guard
        // below (so the client still gets the "you already used this" signal);
        // this guard only rejects methods that are entirely off-step. The
        // empty-set case (flow/step unresolvable) is treated as "do not enforce"
        // to preserve the legacy fail-open behaviour on a broken flow rather than
        // locking every method out.
        Set<AuthMethodType> permittedTypes = resolveCurrentStepPermittedTypes(session);
        boolean alreadyCompletedElsewhere = session.getCompletedMethods().contains(methodType.name());
        if (!permittedTypes.isEmpty() && !permittedTypes.contains(methodType) && !alreadyCompletedElsewhere) {
            log.warn("AUDIT: MFA step rejected — method {} not permitted on step {} for userId={}, ip={}",
                    methodType, session.getCurrentStep(), session.getUserId(), req.clientIp());
            auditLogPort.logMfaStepFailed(session.getUserId().toString(), req.method(),
                    "method_not_permitted_for_step", req.clientIp(), req.userAgent());
            return VerifyMfaStepResponse.methodNotPermitted(
                    session.getCurrentStep(),
                    session.getTotalSteps(),
                    permittedTypes.stream().map(Enum::name)
                            .collect(java.util.stream.Collectors.toCollection(java.util.TreeSet::new)),
                    session.getCompletedMethods());
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
            // SECURITY (2026-06-01): path-independent strike counter — record the
            // failed factor so online guessing through this path trips the lock at
            // MAX_FAILED_ATTEMPTS. We do NOT throw here (returning the structured
            // failure below) so the increment/lock commits; the lock is enforced on
            // the NEXT attempt via enforceLoginAllowed (avoids a rollback-on-throw).
            loginAccountStateGuard.recordFailedAttempt(user.getId(), user.getEmail(), req.clientIp());
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
        // Reset the per-account strike counter on a successful factor (path-independent).
        loginAccountStateGuard.recordSuccess(user.getId());
        // Sliding TTL: a verified step earns more time so a long multi-factor
        // flow (notably a FACE step) doesn't expire the session out from under
        // the user. Capped at MFA_SESSION_MAX_TTL from creation so an abandoned
        // session still dies on a bounded clock. Persisted with the session by
        // the save() that completeMfa / advanceToNextStep already perform — no
        // extra write. Reversible: additive, no schema change.
        extendSessionTtl(session);
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

    /**
     * Slides {@code session.expiresAt} forward by {@link #MFA_SESSION_STEP_EXTENSION}
     * on a successful step, capped at {@link #MFA_SESSION_MAX_TTL} from the
     * session's {@code createdAt}. Never SHRINKS an already-later expiry (e.g. a
     * session created with a longer base TTL), and never extends past the
     * absolute ceiling. Visible-for-test.
     */
    static void extendSessionTtl(MfaSession session) {
        java.time.Instant now = java.time.Instant.now();
        java.time.Instant proposed = now.plus(MFA_SESSION_STEP_EXTENSION);
        java.time.Instant ceiling = session.getCreatedAt() != null
                ? session.getCreatedAt().plus(MFA_SESSION_MAX_TTL)
                : proposed; // defensive: no createdAt → just grant the slide
        java.time.Instant capped = proposed.isAfter(ceiling) ? ceiling : proposed;
        // Only ever move expiry LATER — a step must not be able to shorten a
        // session that was already granted a longer window.
        if (session.getExpiresAt() == null || capped.isAfter(session.getExpiresAt())) {
            session.setExpiresAt(capped);
        }
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

        // #15 — MFA login completed: UPSERT a UserDevice row so the user surfaces
        // in the dashboard Devices view. Best-effort (the impl swallows all errors)
        // so device tracking can never fail the login.
        manageDeviceUseCase.recordLoginDevice(user.getId(), req.userAgent());

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
        // DISPLAY list: the FULL step set (shared resolver — correct PASSWORD rule).
        // Completed methods are NOT filtered out; the client marks them "already used"
        // from `completedMethods` below. The METHOD_ALREADY_USED guard above is the
        // actual enforcement, so showing a used method (disabled) leaks nothing.
        Map<AuthMethodType, Boolean> healthStatus = enrollmentHealthService.validateEnrollments(user.getId());
        List<AvailableMfaMethod> availableMethods = availableMethodsResolver.build(
                nextStep,
                AvailableMethodsResolver.hasPassword(user.getPasswordHash()),
                healthStatus,
                user.getPreferred2faMethod());
        // Internal auto-routing (single-option auto-advance + alternatives) must still
        // ignore already-completed methods so the flow never re-offers a used factor.
        List<AvailableMfaMethod> selectable = availableMethods.stream()
                .filter(m -> !completedSoFar.contains(m.getMethodType()))
                .collect(java.util.stream.Collectors.toList());
        AuthMethodType nextPrimary = nextStep.getAvailableMethods().stream()
                .filter(Objects::nonNull)
                .map(AuthMethod::getType)
                .filter(t -> !completedSoFar.contains(t.name()))
                .findFirst()
                .orElse(null);
        List<AvailableMfaMethod> alternativeMethods = nextPrimary == null
                ? List.of()
                : computeAlternativeMethods(selectable, nextPrimary);

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

    /**
     * Resolves the set of {@link AuthMethodType} a caller is permitted to submit
     * at the session's CURRENT step: the step's available methods (SEQUENTIAL →
     * primary; CHOICE → every alternative) PLUS the configured fallback method.
     * Mirrors the {@code permitted} set computed by
     * {@code AuthController.switchMfaMethod}. Returns an empty set when the flow
     * or step cannot be resolved, which the caller treats as "do not enforce"
     * (legacy fail-open on a broken flow rather than locking the user out).
     */
    private Set<AuthMethodType> resolveCurrentStepPermittedTypes(MfaSession session) {
        try {
            AuthFlow currentFlow = authFlowRepository.findById(session.getFlowId()).orElse(null);
            if (currentFlow == null) return Collections.emptySet();
            int currentStepOrder = session.getCurrentStep();
            AuthFlowStep currentStep = currentFlow.getSteps().stream()
                    .filter(s -> s.getStepOrder() == currentStepOrder)
                    .findFirst()
                    .orElse(null);
            if (currentStep == null) return Collections.emptySet();
            Set<AuthMethodType> permitted = EnumSet.noneOf(AuthMethodType.class);
            for (AuthMethod m : currentStep.getAvailableMethods()) {
                if (m != null && m.getType() != null) {
                    permitted.add(m.getType());
                }
            }
            if (currentStep.getFallbackMethod() != null
                    && currentStep.getFallbackMethod().getType() != null) {
                permitted.add(currentStep.getFallbackMethod().getType());
            }
            return permitted;
        } catch (Exception e) {
            log.warn("Failed to resolve permitted MFA step methods (sessionId={}): {}",
                    session.getId(), e.getMessage());
            return Collections.emptySet();
        }
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
