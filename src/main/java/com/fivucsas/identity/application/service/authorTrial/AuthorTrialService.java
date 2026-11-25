package com.fivucsas.identity.application.service.authorTrial;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.port.input.AuthenticateUserUseCase;
import com.fivucsas.identity.application.port.input.AuthorTrialUseCase;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Attempt;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Finish;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.NewAttempt;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Participant;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.PlanSlot;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.FaceEmbeddingLivenessPolicy;
import com.fivucsas.identity.application.service.LoginAccountStateGuard;
import com.fivucsas.identity.application.service.PuzzleLayerPolicy;
import com.fivucsas.identity.application.service.PuzzleStepConfig;
import com.fivucsas.identity.application.service.authorTrial.AuthorTrialInputSanitizer.SanitizedJson;
import com.fivucsas.identity.domain.exception.NeedsEnrollmentException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.user.User;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.repository.MfaSessionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Authors-only trial orchestrator (V90). It creates a REAL identifier-first MFA
 * session for the bound account, assigns a server-side round-plan slot, records
 * a pending attempt row, and serves the export. The decision fields are written
 * by the real MFA machinery through {@link AuthorTrialRecorder}; this service
 * never writes an accept.
 *
 * <p>No password is involved: the trial tenant's default APP_LOGIN flow starts
 * with a PUZZLE-only step, so `beginIdentifierLogin` opens an MFA session whose
 * first and only factor is the Puzzle + face-identity step. The trial requires
 * exactly one step; a multi-step flow is a configuration error because a step
 * pass would no longer equal a login.
 */
@Service
@Slf4j
public class AuthorTrialService implements AuthorTrialUseCase {

    /** One challenge per attempt is what makes a round cover each puzzle once. */
    static final String TRIAL_DIFFICULTY = "easy";
    static final int TRIAL_COUNT = 1;
    static final int EMBEDDING_DIM = 512;
    private static final Duration BIO_VERSION_TTL = Duration.ofMinutes(10);

    private final AuthorTrialStorePort store;
    private final AuthorTrialProperties properties;
    private final AuthorTrialAccessGuard guard;
    private final UserDomainRepository userDomainRepository;
    private final AuthenticateUserUseCase authenticateUserUseCase;
    private final LoginAccountStateGuard loginAccountStateGuard;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;
    private final BiometricServicePort biometricService;
    private final AuthFlowRepositoryPort authFlowRepository;
    private final PuzzleLayerPolicy puzzleLayerPolicy;
    private final ClientSideEmbeddingPolicy clientSideEmbeddingPolicy;
    private final FaceEmbeddingLivenessPolicy faceEmbeddingLivenessPolicy;
    private final MfaSessionRepository mfaSessionRepository;
    private final ObjectMapper objectMapper;
    private final AuthorTrialInputSanitizer sanitizer;
    private final SecureRandom random = new SecureRandom();

    private volatile String cachedBioVersion;
    private volatile Instant cachedBioVersionAt;

    @Autowired
    public AuthorTrialService(AuthorTrialStorePort store,
                              AuthorTrialProperties properties,
                              AuthorTrialAccessGuard guard,
                              UserDomainRepository userDomainRepository,
                              AuthenticateUserUseCase authenticateUserUseCase,
                              LoginAccountStateGuard loginAccountStateGuard,
                              ManageEnrollmentUseCase manageEnrollmentUseCase,
                              BiometricServicePort biometricService,
                              AuthFlowRepositoryPort authFlowRepository,
                              PuzzleLayerPolicy puzzleLayerPolicy,
                              ClientSideEmbeddingPolicy clientSideEmbeddingPolicy,
                              FaceEmbeddingLivenessPolicy faceEmbeddingLivenessPolicy,
                              MfaSessionRepository mfaSessionRepository,
                              ObjectMapper objectMapper) {
        this.store = store;
        this.properties = properties;
        this.guard = guard;
        this.userDomainRepository = userDomainRepository;
        this.authenticateUserUseCase = authenticateUserUseCase;
        this.loginAccountStateGuard = loginAccountStateGuard;
        this.manageEnrollmentUseCase = manageEnrollmentUseCase;
        this.biometricService = biometricService;
        this.authFlowRepository = authFlowRepository;
        this.puzzleLayerPolicy = puzzleLayerPolicy;
        this.clientSideEmbeddingPolicy = clientSideEmbeddingPolicy;
        this.faceEmbeddingLivenessPolicy = faceEmbeddingLivenessPolicy;
        this.mfaSessionRepository = mfaSessionRepository;
        this.objectMapper = objectMapper;
        this.sanitizer = new AuthorTrialInputSanitizer(objectMapper);
    }

    // ------------------------------------------------------------------
    // Participants
    // ------------------------------------------------------------------

    @Override
    @Transactional(readOnly = true)
    public ParticipantsView participants() {
        UUID tenant = requireTenant();
        FlowPolicy flow = requireFlow(tenant);
        List<ParticipantView> list = store.participants(tenant).stream()
                .map(p -> new ParticipantView(p.code(), p.enrolledAt() != null))
                .toList();
        return new ParticipantsView(tenant, list,
                new FlowView("PUZZLE", flow.binding(), TRIAL_DIFFICULTY, TRIAL_COUNT, flow.challenges()));
    }

    // ------------------------------------------------------------------
    // Session creation
    // ------------------------------------------------------------------

    @Override
    @Transactional
    public SessionView startSession(StartRequest request, String clientIp, String userAgent) {
        UUID tenant = requireTenant();
        if (request == null) {
            throw AuthorTrialException.badRequest("TRIAL_BAD_REQUEST", "Request body is required");
        }
        String mode = normalizeMode(request.mode());
        Participant operator = requireParticipant(tenant, requireCode(request.participantCode()));
        Participant target = "genuine".equals(mode)
                ? operator
                : requireParticipant(tenant, requireCode(request.targetCode()));
        if ("attack".equals(mode) && target.code().equals(operator.code())) {
            throw AuthorTrialException.badRequest("TRIAL_TARGET_MUST_DIFFER",
                    "Attack mode needs a target different from the participant");
        }
        String instrument = sanitizer.instrument(request.instrument());
        String preset = sanitizer.preset(request.instrumentPreset());
        if ("attack".equals(mode) && instrument == null) {
            throw AuthorTrialException.badRequest("TRIAL_INSTRUMENT_REQUIRED",
                    "Attack mode requires the attack instrument name");
        }
        FlowPolicy flow = requireFlow(tenant);

        // A genuine rejection must never lock the bound account and stop the loop.
        // clearLock is REQUIRES_NEW (commits independently) and resets the counter.
        loginAccountStateGuard.clearLock(target.userId());

        User targetUser = userDomainRepository.findById(target.userId())
                .orElseThrow(() -> AuthorTrialException.conflict("TRIAL_USER_NOT_FOUND",
                        "The bound account of %s no longer exists".formatted(target.code())));
        if (targetUser.getTenantId() == null || !targetUser.getTenantId().equals(tenant)) {
            throw AuthorTrialException.conflict("TRIAL_USER_TENANT_MISMATCH",
                    "The bound account is not in the trial tenant");
        }

        PlanSlot slot = claimSlot(tenant, operator.code(), mode, flow.challenges());

        AuthenticationResponse auth;
        try {
            auth = authenticateUserUseCase.beginIdentifierLogin(
                    targetUser.getEmail(), null, clientIp, userAgent);
        } catch (NeedsEnrollmentException e) {
            throw AuthorTrialException.conflict("TRIAL_NOT_ENROLLED",
                    "Enroll the participant on the trial page first");
        } catch (RuntimeException e) {
            log.warn("AUDIT: author-trial begin failed — participant={}, target={}, reason={}",
                    operator.code(), target.code(), e.getClass().getSimpleName());
            throw AuthorTrialException.conflict("TRIAL_LOGIN_BEGIN_FAILED",
                    "Could not open the trial MFA session");
        }
        if (auth == null || auth.getMfaSessionToken() == null || auth.getMfaSessionToken().isBlank()) {
            throw AuthorTrialException.conflict("TRIAL_LOGIN_BEGIN_FAILED",
                    "Could not open the trial MFA session");
        }
        if (!AuthMethodType.PUZZLE.name().equals(auth.getTwoFactorMethod())) {
            throw AuthorTrialException.conflict("TRIAL_FLOW_NOT_PUZZLE_FIRST",
                    "The trial flow's first method is not PUZZLE");
        }
        if (auth.getTotalSteps() == null || auth.getTotalSteps() != 1) {
            throw AuthorTrialException.conflict("TRIAL_FLOW_MULTI_STEP",
                    "The trial flow must have exactly one step (PUZZLE)");
        }
        MfaSession mfaSession = mfaSessionRepository.findBySessionToken(auth.getMfaSessionToken())
                .orElseThrow(() -> AuthorTrialException.conflict("TRIAL_LOGIN_BEGIN_FAILED",
                        "The trial MFA session was not persisted"));

        SanitizedJson device = sanitizer.device(request.device(), properties.getDeviceMaxBytes());
        SanitizedJson env = sanitizer.environment(request.env(), properties.getEnvMaxBytes());
        String webVersion = sanitizer.version(request.webVersion());
        String livenessMode = faceEmbeddingLivenessPolicy.modeFor(tenant)
                .name().toLowerCase(Locale.ROOT);
        Instant now = Instant.now();

        UUID attemptId = store.createAttempt(new NewAttempt(
                tenant, operator.code(), mode, target.code(), instrument, preset,
                slot.challenge(), slot.challenge(), slot.roundNo(), slot.position(), slot.id(),
                flow.binding(), TRIAL_DIFFICULTY, TRIAL_COUNT, livenessMode,
                mfaSession.getId(), now, device.json(), env.json(), webVersion,
                properties.getApiVersion(), bioVersion()));
        store.assignSlot(slot.id(), attemptId);

        log.info("AUDIT: author-trial attempt started — attemptId={}, participant={}, target={}, "
                        + "mode={}, round={}, position={}, challenge={}",
                attemptId, operator.code(), target.code(), mode,
                slot.roundNo(), slot.position(), slot.challenge());

        return new SessionView(attemptId, auth.getMfaSessionToken(),
                operator.code(), target.code(), mode, slot.roundNo(), slot.position(),
                slot.challenge(), flow.binding(), TRIAL_DIFFICULTY, TRIAL_COUNT,
                new PuzzleConfigView(List.of(slot.challenge()), TRIAL_COUNT,
                        TRIAL_DIFFICULTY, flow.binding()));
    }

    // ------------------------------------------------------------------
    // Finish (technical status, never an accept)
    // ------------------------------------------------------------------

    @Override
    @Transactional
    public FinishView finish(UUID attemptId, FinishRequest request) {
        UUID tenant = requireTenant();
        Attempt attempt = store.attempt(attemptId)
                .orElseThrow(() -> AuthorTrialException.notFound("TRIAL_ATTEMPT_NOT_FOUND"));
        if (!tenant.equals(attempt.tenantId())) {
            throw AuthorTrialException.notFound("TRIAL_ATTEMPT_NOT_FOUND");
        }
        String clientOutcome = normalizeClientOutcome(request == null ? null : request.clientOutcome());
        String reason = request == null ? null : sanitizer.reason(request.failureReason());
        SanitizedJson device = request == null || request.device() == null
                ? null : sanitizer.device(request.device(), properties.getDeviceMaxBytes());
        SanitizedJson env = request == null || request.env() == null
                ? null : sanitizer.environment(request.env(), properties.getEnvMaxBytes());
        store.recordFinish(attemptId, new Finish(clientOutcome, reason,
                request == null ? null : request.clientLatencyMs(),
                device == null ? null : device.json(),
                env == null ? null : env.json(), Instant.now()));

        Attempt updated = store.attempt(attemptId).orElse(attempt);
        String outcome = updated.outcome();
        boolean excluded = outcome == null || "error".equals(outcome) || "abandoned".equals(outcome);
        return new FinishView(outcome, excluded, updated.failureReason());
    }

    // ------------------------------------------------------------------
    // Enrollment
    // ------------------------------------------------------------------

    @Override
    @Transactional
    public EnrollView enroll(EnrollRequest request) {
        UUID tenant = requireTenant();
        if (request == null) {
            throw AuthorTrialException.badRequest("TRIAL_BAD_REQUEST", "Request body is required");
        }
        Participant participant = requireParticipant(tenant, requireCode(request.participantCode()));
        List<Double> embedding = request.embedding();
        if (embedding == null || embedding.size() != EMBEDDING_DIM) {
            throw AuthorTrialException.badRequest("TRIAL_EMBEDDING_512_REQUIRED",
                    "embedding must be a 512-float vector");
        }
        for (Double value : embedding) {
            if (value == null || !Double.isFinite(value)) {
                throw AuthorTrialException.badRequest("TRIAL_EMBEDDING_INVALID",
                        "embedding contains a non-finite value");
            }
        }
        User user = userDomainRepository.findById(participant.userId())
                .orElseThrow(() -> AuthorTrialException.conflict("TRIAL_USER_NOT_FOUND",
                        "The bound account no longer exists"));
        if (user.getTenantId() == null || !user.getTenantId().equals(tenant)) {
            throw AuthorTrialException.conflict("TRIAL_USER_TENANT_MISMATCH",
                    "The bound account is not in the trial tenant");
        }

        Map<String, Object> response;
        try {
            response = biometricService.enrollEmbedding(tenant.toString(), participant.userId(), embedding);
        } catch (RuntimeException e) {
            log.warn("author-trial enroll failed for {}: {}", participant.code(), e.getMessage());
            throw AuthorTrialException.upstream("TRIAL_ENROLL_FAILED", "Biometric enrollment failed");
        }
        if (response == null || Boolean.FALSE.equals(response.get("success"))) {
            String message = response == null ? "" : String.valueOf(response.getOrDefault("message", ""));
            if (message.contains("FACE_IMAGE_REQUIRED")) {
                throw AuthorTrialException.conflict("TRIAL_ENROLL_IMAGE_REQUIRED",
                        "The face-embedding enrollment was refused; keep the trial tenant's "
                                + "face-embedding liveness mode at AUDIT/OFF");
            }
            throw AuthorTrialException.upstream("TRIAL_ENROLL_FAILED",
                    message.isBlank() ? "Biometric enrollment failed" : message);
        }

        // Complete the FACE + PUZZLE enrollment rows the login flow checks.
        manageEnrollmentUseCase.completeEnrollment(participant.userId(), AuthMethodType.FACE, "{}");
        manageEnrollmentUseCase.completeEnrollment(participant.userId(), AuthMethodType.PUZZLE, "{}");
        store.markEnrolled(participant.id(), Instant.now());
        log.info("AUDIT: author-trial participant enrolled — code={}, tenant={}",
                participant.code(), tenant);
        return new EnrollView(true);
    }

    // ------------------------------------------------------------------
    // Export
    // ------------------------------------------------------------------

    @Override
    @Transactional(readOnly = true)
    public ExportView export(String format) {
        UUID tenant = requireTenant();
        List<Attempt> attempts = store.attemptsForExport(tenant, properties.getExportLimit());
        if ("json".equalsIgnoreCase(format == null ? "" : format.trim())) {
            try {
                return new ExportView(
                        objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(attempts),
                        "application/json", "author_trial_sessions.json");
            } catch (JsonProcessingException e) {
                throw new IllegalStateException("author-trial JSON export failed", e);
            }
        }
        Map<String, Integer> sessionNumbers = new HashMap<>();
        List<AuthorTrialCsv.Row> rows = attempts.stream()
                .map(a -> new AuthorTrialCsv.Row(a,
                        sessionNumbers.merge(a.targetCode() == null ? "?" : a.targetCode(), 1, Integer::sum)))
                .toList();
        return new ExportView(AuthorTrialCsv.render(rows, objectMapper),
                "text/csv; charset=utf-8", "author_trial_sessions.csv");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private UUID requireTenant() {
        return guard.trialTenantId()
                .orElseThrow(() -> AuthorTrialException.notFound("AUTHOR_TRIAL_DISABLED"));
    }

    private Participant requireParticipant(UUID tenant, String code) {
        return store.participant(tenant, code)
                .orElseThrow(() -> AuthorTrialException.notFound("TRIAL_PARTICIPANT_UNKNOWN"));
    }

    private FlowPolicy requireFlow(UUID tenant) {
        if (!puzzleLayerPolicy.isEnabledFor(tenant)) {
            throw AuthorTrialException.conflict("TRIAL_PUZZLE_LAYER_DISABLED",
                    "The PUZZLE layer is not enabled for the trial tenant");
        }
        AuthFlow flow = authFlowRepository
                .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(tenant, OperationType.APP_LOGIN)
                .orElseThrow(() -> AuthorTrialException.conflict("TRIAL_FLOW_NOT_CONFIGURED",
                        "No active default APP_LOGIN flow for the trial tenant"));
        AuthFlowStep step1 = flow.getSteps() == null ? null : flow.getSteps().stream()
                .filter(s -> s != null && s.getStepOrder() == 1)
                .findFirst()
                .orElse(null);
        if (step1 == null || step1.getAvailableMethods() == null
                || step1.getAvailableMethods().stream()
                .noneMatch(m -> m != null && m.getType() == AuthMethodType.PUZZLE)) {
            throw AuthorTrialException.conflict("TRIAL_FLOW_NOT_PUZZLE_FIRST",
                    "Step 1 of the default APP_LOGIN flow must include PUZZLE");
        }
        PuzzleStepConfig config = PuzzleStepConfig.parse(step1.getConfig())
                .filter(PuzzleStepConfig::hasChallenges)
                .orElseThrow(() -> AuthorTrialException.conflict("TRIAL_FLOW_NOT_CONFIGURED",
                        "The PUZZLE step has no usable puzzleConfig"));
        if (!config.unknownChallengeTypes().isEmpty()) {
            throw AuthorTrialException.conflict("TRIAL_FLOW_UNKNOWN_CHALLENGES",
                    "Unknown challenge types in the trial flow: " + config.unknownChallengeTypes());
        }
        if (config.alsoMatchFaceIdentity()
                && !clientSideEmbeddingPolicy.isEnabledForTenant(tenant)) {
            // Binding is part of the owner's design ("Puzzle + face verification");
            // with the embedding path off the step would silently be liveness-only.
            throw AuthorTrialException.conflict("TRIAL_EMBEDDING_DISABLED",
                    "Client-side face embedding is not enabled for the trial tenant");
        }
        return new FlowPolicy(config.allowedChallengeTypes(), config.alsoMatchFaceIdentity());
    }

    private PlanSlot claimSlot(UUID tenant, String participantCode, String mode, List<String> challenges) {
        Optional<PlanSlot> free = store.lockNextFreeSlot(tenant, participantCode, mode);
        if (free.isPresent()) {
            return free.get();
        }
        int roundNo = store.maxRound(tenant, participantCode, mode) + 1;
        List<String> shuffled = new ArrayList<>(challenges);
        Collections.shuffle(shuffled, random);
        store.createRound(tenant, participantCode, mode, roundNo, shuffled);
        return store.lockNextFreeSlot(tenant, participantCode, mode)
                .orElseThrow(() -> AuthorTrialException.conflict("TRIAL_PLAN_FAILED",
                        "Could not allocate a round slot"));
    }

    private String normalizeMode(String raw) {
        String value = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        if ("genuine".equals(value) || "attack".equals(value)) {
            return value;
        }
        throw AuthorTrialException.badRequest("TRIAL_BAD_MODE", "mode must be genuine or attack");
    }

    private String normalizeClientOutcome(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if ("accepted".equals(value) || "rejected".equals(value)
                || "error".equals(value) || "abandoned".equals(value)) {
            return value;
        }
        throw AuthorTrialException.badRequest("TRIAL_BAD_CLIENT_OUTCOME",
                "clientOutcome must be accepted, rejected, error or abandoned");
    }

    private String requireCode(String raw) {
        String value = raw == null ? "" : raw.trim().toUpperCase(Locale.ROOT);
        if (value.isEmpty() || value.length() > 16) {
            throw AuthorTrialException.badRequest("TRIAL_BAD_PARTICIPANT_CODE",
                    "participantCode is required");
        }
        return value;
    }

    /** Bio's own version, cached; the deploy pin fallback when the probe fails. */
    private String bioVersion() {
        String cached = cachedBioVersion;
        Instant at = cachedBioVersionAt;
        if (cached != null && at != null && Duration.between(at, Instant.now()).compareTo(BIO_VERSION_TTL) < 0) {
            return cached;
        }
        String version = properties.getFallbackBioVersion();
        try {
            Map<String, Object> health = biometricService.checkHealth();
            if (health != null && health.get("version") != null) {
                version = String.valueOf(health.get("version"));
            }
        } catch (RuntimeException e) {
            log.debug("author-trial bio version probe failed: {}", e.getMessage());
        }
        cachedBioVersion = version;
        cachedBioVersionAt = Instant.now();
        return version;
    }

    private record FlowPolicy(List<String> challenges, boolean binding) {}
}