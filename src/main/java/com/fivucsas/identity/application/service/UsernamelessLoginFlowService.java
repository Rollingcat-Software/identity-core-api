package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
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
            long expiresIn) {

        public static FlowOutcome pending(String token, int currentStep, int totalSteps) {
            return new FlowOutcome(true, token, currentStep, totalSteps, null, null, 0L);
        }

        public static FlowOutcome minted(String accessToken, String refreshToken, long expiresIn) {
            return new FlowOutcome(false, null, 0, 0, accessToken, refreshToken, expiresIn);
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
    @Transactional
    public FlowOutcome continueAfterLayer1(User user, AuthMethodType layer1Method, String amr,
                                           String ip, String userAgent, String clientId) {
        Optional<AuthFlow> defaultLoginFlow = user.getTenant() == null
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

                log.info("AUDIT: usernameless Layer-1 {} → MFA required — userId={}, remainingSteps={}, ip={}",
                        layer1Method, user.getId(), remainingSteps.size(), ip);

                return FlowOutcome.pending(sessionToken, 2, flow.getStepCount());
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

    private boolean stepHasEnrollment(AuthFlowStep step, Map<AuthMethodType, Boolean> healthStatus) {
        return step.getAvailableMethods().stream()
                .filter(Objects::nonNull)
                .filter(AuthMethod::isRequiresEnrollment)
                .filter(m -> !m.isSupportsUsernameless())
                .anyMatch(m -> Boolean.TRUE.equals(healthStatus.get(m.getType())));
    }
}
