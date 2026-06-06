package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Bridges a usernameless / cross-device Layer-1 login (discoverable passkey,
 * approve-login number-matching, QR scan-to-approve) INTO the tenant's
 * config-driven APP_LOGIN flow (task #16 B).
 *
 * <p>Historically these three entry points minted a full access + refresh token
 * the instant the Layer-1 factor verified, completely bypassing any Layer-2+
 * steps the tenant configured. After this service they behave exactly like
 * {@code AuthenticateUserService}: once the Layer-1 factor is proven we look up
 * the tenant default APP_LOGIN flow; if any steps remain beyond step 1 we create
 * an {@link MfaSession} (currentStep=2, completedMethods=[that Layer-1 method])
 * and return {@code MFA_PENDING} — the caller surfaces a session token instead
 * of tokens. Only a 1-step (or no-flow) tenant mints tokens immediately, with
 * {@code amr} seeded from the Layer-1 method.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UsernamelessLoginFlowService {

    private final AuthFlowRepositoryPort authFlowRepository;
    private final EnrollmentHealthService enrollmentHealthService;
    private final MfaSessionRepository mfaSessionRepository;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final ConfigDrivenLoginPolicy configDrivenLoginPolicy;
    private final UserEnrollmentRepositoryPort userEnrollmentRepository;

    private static final Duration MFA_SESSION_TTL = Duration.ofMinutes(10);

    /**
     * Outcome of bridging a Layer-1 factor into the flow. Exactly one of
     * {@code mfaPending}/minted is meaningful:
     * <ul>
     *   <li>{@code mfaPending == true}  → {@code mfaSessionToken} + step info are
     *       set; {@code accessToken}/{@code refreshToken} are null. The Layer-1
     *       factor is proven but the flow needs more steps.</li>
     *   <li>{@code mfaPending == false} → tokens are set; the flow was 1-step or
     *       the tenant has no default flow.</li>
     * </ul>
     */
    public record FlowOutcome(
            boolean mfaPending,
            String mfaSessionToken,
            int currentStep,
            int totalSteps,
            String accessToken,
            String refreshToken,
            long expiresIn,
            List<String> availableMethods) {

        /**
         * @param availableMethods the selectable {@link AuthMethodType} NAME strings
         *        the caller may present for the FIRST remaining step (the next step
         *        after the proven Layer-1 factor). For a SEQUENTIAL step this is the
         *        single primary method; for a CHOICE step it is every alternative.
         *        Lets the polling web client render the method picker without a
         *        second round-trip (task #16 B / issue #2/#6). Always non-null
         *        (empty list when nothing could be resolved); older callers/clients
         *        simply ignore it.
         */
        public static FlowOutcome pending(String token, int currentStep, int totalSteps,
                                          List<String> availableMethods) {
            return new FlowOutcome(true, token, currentStep, totalSteps, null, null, 0L,
                    availableMethods != null ? List.copyOf(availableMethods) : List.of());
        }

        public static FlowOutcome minted(String accessToken, String refreshToken, long expiresIn) {
            return new FlowOutcome(false, null, 0, 0, accessToken, refreshToken, expiresIn, List.of());
        }
    }

    /**
     * Resolve the post-Layer-1 outcome for {@code user} whose Layer-1 factor
     * {@code layer1Method} (e.g. PASSKEY, APPROVE_LOGIN, QR_CODE) has just been
     * cryptographically proven.
     *
     * @param amr       RFC 8176 amr value to record for the Layer-1 factor when
     *                  minting a 1-step token (e.g. "webauthn", "approve_login").
     * @param ip        request IP (recorded on a minted refresh token / session)
     * @param userAgent request UA (recorded on a minted refresh token / session)
     * @param clientId  OAuth2 client_id that initiated the login (nullable);
     *                  bound to the MFA session for cross-client replay defense.
     */
    /**
     * Whether the config-driven flow handoff applies to {@code user}'s tenant.
     * Call sites that have their OWN legacy minting path (QR / approve-login)
     * check this FIRST and skip the bridge entirely when OFF, so their OFF-path
     * token issuance stays byte-identical. Passkey has no separate legacy path,
     * so it always calls {@link #continueAfterLayer1} which mints directly when
     * the flow is 1-step / OFF.
     */
    public boolean isConfigDrivenFor(User user) {
        return user.getTenant() != null
                && configDrivenLoginPolicy.isEnabledFor(user.getTenant().getId());
    }

    @Transactional
    public FlowOutcome continueAfterLayer1(User user, AuthMethodType layer1Method, String amr,
                                           String ip, String userAgent, String clientId) {
        // Issue #3: APPROVE_LOGIN / PASSKEY are device-implicit factors — there is
        // no separate "enroll" ceremony, so proving one (signing in from the mobile
        // app / a usernameless Layer-1 path) is itself the enrollment. Ensure an
        // ENROLLED APPROVE_LOGIN user_enrollments row exists for this user so the
        // web Enrollments page stops reporting "not enrolled". Idempotent + additive
        // + best-effort (never fails the login). Reversible: the row can be revoked
        // via the existing enrollment-revoke path with no behavior change.
        ensureApproveLoginEnrollment(user);

        // The flow handoff (MFA_PENDING) only applies when the engine is enabled
        // (global flag or per-tenant canary). When OFF we mint directly — for
        // passkey this matches its legacy single-factor behavior exactly.
        Optional<AuthFlow> defaultLoginFlow = !isConfigDrivenFor(user)
                ? Optional.empty()
                : authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                        user.getTenant().getId(), OperationType.APP_LOGIN);

        if (defaultLoginFlow.isPresent()) {
            AuthFlow flow = defaultLoginFlow.get();

            Map<AuthMethodType, Boolean> healthStatus =
                    enrollmentHealthService.validateEnrollments(user.getId());

            // Steps beyond step 1: Layer-1 already satisfied the first step. As in
            // AuthenticateUserService, optional steps the user has no enrollment for
            // are skipped so we don't strand them in a loop.
            List<AuthFlowStep> remainingSteps = flow.getSteps().stream()
                    .filter(step -> step.getStepOrder() > 1)
                    .sorted(Comparator.comparingInt(AuthFlowStep::getStepOrder))
                    .filter(step -> step.isRequired() || stepHasEnrollment(step, healthStatus))
                    .toList();

            if (!remainingSteps.isEmpty()) {
                String sessionToken = UUID.randomUUID().toString().replace("-", "");
                String stepsData = "[\"" + layer1Method.name() + "\"]";
                MfaSession mfaSession = MfaSession.builder()
                        .sessionToken(sessionToken)
                        .userId(user.getId())
                        .tenantId(user.getTenant().getId())
                        .flowId(flow.getId())
                        .currentStep(2)  // step 1 (the usernameless Layer-1) already done
                        .totalSteps(flow.getStepCount())
                        .stepsData(stepsData)
                        .ipAddress(ip)
                        .userAgent(userAgent)
                        .clientId(clientId)
                        .expiresAt(Instant.now().plus(MFA_SESSION_TTL))
                        .build();
                mfaSessionRepository.save(mfaSession);

                // The web method-picker needs the NEXT step's selectable methods to
                // render (issue #2/#6: "approved on phone but web can't continue").
                // Derive them from the FIRST remaining step: its primary method for a
                // SEQUENTIAL step, or every alternative for a CHOICE step
                // (AuthFlowStep.getAvailableMethods() already encodes that rule).
                List<String> availableMethods = remainingSteps.get(0).getAvailableMethods().stream()
                        .filter(Objects::nonNull)
                        .map(AuthMethod::getType)
                        .filter(Objects::nonNull)
                        .map(AuthMethodType::name)
                        .distinct()
                        .toList();

                log.info("AUDIT: usernameless Layer-1 {} → MFA required — userId={}, remainingSteps={}, nextMethods={}, ip={}",
                        layer1Method, user.getId(), remainingSteps.size(), availableMethods, ip);

                return FlowOutcome.pending(sessionToken, 2, flow.getStepCount(), availableMethods);
            }
        }

        // 1-step flow (or no default flow): mint immediately.
        String accessToken = tokenGenerator.generateAccessToken(user.getEmail(), List.of(amr));
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, ip, userAgent);
        long expiresIn = tokenGenerator.getExpirationMillis();
        log.info("AUDIT: usernameless Layer-1 {} → single-factor login — userId={}, ip={}",
                layer1Method, user.getId(), ip);
        return FlowOutcome.minted(accessToken, refreshToken.getToken(), expiresIn);
    }

    /**
     * Idempotently ensures the user has an ENROLLED {@link AuthMethodType#APPROVE_LOGIN}
     * enrollment record (issue #3). APPROVE_LOGIN is device-implicit: there is no
     * upload/secret to bind (it is the cross-device number-matching approval the
     * user's registered device performs), so a successful usernameless login is the
     * enrollment event. This mirrors the lazy session-bound upsert pattern used for
     * EMAIL_OTP / QR_CODE in {@code ManageEnrollmentService.ensureAutoBoundEnrollment}.
     *
     * <p>Idempotent: if any APPROVE_LOGIN row already exists (including REVOKED — a
     * user who explicitly removed it stays removed) we leave it alone. Best-effort:
     * a missing tenant or a unique-constraint race is swallowed so login is never
     * failed by this bookkeeping. The row's tenant is the owning user's tenant, so
     * the Hibernate {@code tenantFilter} insert stays consistent (P0-1).
     */
    private void ensureApproveLoginEnrollment(User user) {
        try {
            if (user == null || user.getTenant() == null) {
                return;
            }
            if (userEnrollmentRepository
                    .findByUserIdAndAuthMethodType(user.getId(), AuthMethodType.APPROVE_LOGIN)
                    .isPresent()) {
                return;
            }
            UserEnrollment enrollment = UserEnrollment.builder()
                    .user(user)
                    .tenant(user.getTenant())
                    .authMethodType(AuthMethodType.APPROVE_LOGIN)
                    .build();
            enrollment.completeEnrollment("{}");
            userEnrollmentRepository.save(enrollment);
            log.info("AUDIT: APPROVE_LOGIN enrollment auto-created on usernameless login — userId={}", user.getId());
        } catch (Exception e) {
            // Includes a concurrent writer winning the (user_id, auth_method_type)
            // unique constraint — the row exists either way, which is the goal.
            log.debug("APPROVE_LOGIN auto-enrollment skipped for user {}: {}",
                    user != null ? user.getId() : null, e.getMessage());
        }
    }

    private boolean stepHasEnrollment(AuthFlowStep step, Map<AuthMethodType, Boolean> healthStatus) {
        return step.getAvailableMethods().stream()
                .filter(Objects::nonNull)
                .filter(AuthMethod::isRequiresEnrollment)
                .filter(m -> !m.isSupportsUsernameless())
                .anyMatch(m -> Boolean.TRUE.equals(healthStatus.get(m.getType())));
    }
}
