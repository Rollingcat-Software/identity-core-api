package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.AuthenticateUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.NeedsEnrollmentException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.auth.StepType;

import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.dto.AvailableMfaMethod;
import com.fivucsas.identity.entity.*;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.service.RefreshTokenService;
import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Use case service for user authentication.
 *
 * Implements the AuthenticateUserUseCase input port.
 * Enforces account lockout after consecutive failed login attempts.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticateUserService implements AuthenticateUserUseCase {

    private final UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogPort auditLogPort;
    private final com.fivucsas.identity.application.port.output.EventPublisherPort eventPublisher;
    private final AuthFlowRepositoryPort authFlowRepository;
    private final OAuth2ClientRepositoryPort oAuth2ClientRepository;
    private final UserEnrollmentRepository userEnrollmentRepository;
    private final MfaSessionRepository mfaSessionRepository;
    private final EnrollmentHealthService enrollmentHealthService;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    private static final Duration MFA_SESSION_TTL = Duration.ofMinutes(10);

    @Override
    @Transactional
    public AuthenticationResponse execute(AuthenticateUserCommand command) {
        log.info("AUDIT: Login attempt — email={}, ip={}", command.getEmail(), command.getIpAddress());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(InvalidCredentialsException::new);

        // Check if account is locked
        if (user.isLocked()) {
            if (user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
                // Lock period expired, auto-unlock
                user.resetFailedLoginAttempts();
                userRepository.save(user);
                log.info("Account auto-unlocked after lockout period for user: {}", command.getEmail());
            } else {
                log.warn("AUDIT: Login failed — email={}, reason: account_locked, ip={}", command.getEmail(), command.getIpAddress());
                auditLogPort.logAuthenticationFailed(command.getEmail(), command.getIpAddress(), "Account locked");
                throw new InvalidCredentialsException("Account is temporarily locked due to too many failed login attempts. Please try again later.");
            }
        }

        // Tenant lock — when the login originates from an OAuth client that is
        // bound to a specific tenant (e.g. demo.fivucsas.com → marmara-bys-demo
        // → Marmara University), refuse the login if the user belongs to a
        // different tenant. Without this gate any user from any tenant could
        // sign in on a tenant-branded surface (the user reported logging into
        // demo.fivucsas.com with their Fivucsas-tenant account on 2026-04-28).
        // Reject BEFORE the password check so we don't leak whether the email
        // exists; surface the same InvalidCredentialsException.
        if (command.getClientId() != null && !command.getClientId().isBlank()) {
            try {
                Optional<OAuth2Client> tenantBoundClient =
                        oAuth2ClientRepository.findByClientId(command.getClientId());
                if (tenantBoundClient.isPresent() && tenantBoundClient.get().getTenant() != null) {
                    UUID clientTenantId = tenantBoundClient.get().getTenant().getId();
                    UUID systemTenantId = UUID.fromString("00000000-0000-0000-0000-000000000000");
                    // Only enforce on tenant-scoped clients (system-tenant clients are
                    // intentionally cross-tenant — e.g. fivucsas-web-dashboard).
                    if (clientTenantId != null
                            && !clientTenantId.equals(systemTenantId)
                            && user.getTenant() != null
                            && !clientTenantId.equals(user.getTenant().getId())) {
                        log.warn("AUDIT: Login refused — tenant mismatch, email={}, " +
                                        "userTenant={}, clientTenant={}, clientId={}, ip={}",
                                command.getEmail(), user.getTenant().getId(), clientTenantId,
                                command.getClientId(), command.getIpAddress());
                        auditLogPort.logAuthenticationFailed(command.getEmail(),
                                command.getIpAddress(),
                                "Tenant mismatch for OAuth client " + command.getClientId());
                        throw new InvalidCredentialsException();
                    }
                }
            } catch (InvalidCredentialsException e) {
                throw e;
            } catch (Exception e) {
                log.warn("Tenant-lock check failed for client '{}': {}",
                        command.getClientId(), e.getMessage());
            }
        }

        if (!passwordEncoder.matches(command.getPassword(), user.getPasswordHash())) {
            // Increment failed attempts and potentially lock account
            user.incrementFailedLoginAttempts();
            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.lockAccount(LOCKOUT_DURATION);
                log.warn("AUDIT: Account locked — email={}, failedAttempts={}, ip={}", command.getEmail(), MAX_FAILED_ATTEMPTS, command.getIpAddress());
                auditLogPort.logAuthenticationFailed(command.getEmail(), command.getIpAddress(),
                        "Account locked after " + MAX_FAILED_ATTEMPTS + " failed attempts");
            } else {
                auditLogPort.logAuthenticationFailed(command.getEmail(), command.getIpAddress(),
                        "Invalid password (attempt " + user.getFailedLoginAttempts() + "/" + MAX_FAILED_ATTEMPTS + ")");
            }
            userRepository.save(user);
            log.warn("AUDIT: Login failed — email={}, reason: invalid_password, attempt: {}/{}, ip={}",
                    command.getEmail(), user.getFailedLoginAttempts(), MAX_FAILED_ATTEMPTS, command.getIpAddress());
            throw new InvalidCredentialsException();
        }

        // Successful login — reset failed attempts and record login metadata
        if (user.getFailedLoginAttempts() > 0) {
            user.resetFailedLoginAttempts();
        }
        user.recordLogin(command.getIpAddress());

        log.info("AUDIT: User authenticated — method: PASSWORD, userId={}, ip={}, userAgent={}",
                user.getId(), command.getIpAddress(), command.getUserAgent());

        // Look up OAuth client name if login came from a widget/OAuth flow
        String oauthClientName = null;
        if (command.getClientId() != null && !command.getClientId().isBlank()) {
            try {
                Optional<OAuth2Client> oauthClient = oAuth2ClientRepository.findByClientId(command.getClientId());
                oauthClientName = oauthClient.map(OAuth2Client::getClientName).orElse(null);
            } catch (Exception e) {
                log.warn("Failed to look up OAuth client '{}': {}", command.getClientId(), e.getMessage());
            }
        }

        if (oauthClientName != null) {
            auditLogPort.logUserAuthenticated(user.getId().toString(), user.getEmail(), command.getIpAddress(), command.getUserAgent(), oauthClientName);
        } else {
            auditLogPort.logUserAuthenticated(user.getId().toString(), user.getEmail(), command.getIpAddress(), command.getUserAgent());
        }
        eventPublisher.publishUserAuthenticated(user.getId().toString(), user.getEmail());

        // Save user (resets failed attempts + updates lastLoginAt if needed)
        userRepository.save(user);

        UserResponse userResponse = com.fivucsas.identity.application.mapper.UserResponseMapper.toResponse(user);

        // Check if tenant's default APP_LOGIN auth flow has additional steps beyond PASSWORD
        try {
            Optional<AuthFlow> defaultLoginFlow = authFlowRepository
                .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                    user.getTenant().getId(), OperationType.APP_LOGIN);

            if (defaultLoginFlow.isPresent()) {
                AuthFlow flow = defaultLoginFlow.get();

                // Find steps beyond step 1 (password was already verified above).
                // Optional steps are skipped when the user has no enrollment in any
                // enrollment-requiring method for that step — avoids forcing repeated
                // EMAIL_OTP loops on users who haven't set up biometric MFA yet.
                Map<AuthMethodType, Boolean> healthStatus =
                    enrollmentHealthService.validateEnrollments(user.getId());

                List<AuthFlowStep> remainingSteps = flow.getSteps().stream()
                    .filter(step -> step.getStepOrder() > 1)
                    .sorted(Comparator.comparingInt(AuthFlowStep::getStepOrder))
                    .filter(step -> step.isRequired() || stepHasBiometricEnrollment(step, healthStatus))
                    .toList();

                if (!remainingSteps.isEmpty()) {
                    // Post-audit 2026-04-24 login edge case #5 — dead-end prevention.
                    // Before committing the user to a multi-step flow, verify every
                    // REQUIRED step has either a method the user is enrolled in or
                    // a configured fallback. Otherwise we would authenticate PASSWORD
                    // and then strand them mid-flow with no way to proceed.
                    verifyUserCanCompleteFlow(user, remainingSteps);

                    // MFA required — DO NOT issue JWT yet. Only create MFA session.
                    AuthFlowStep nextStep = remainingSteps.get(0);
                    List<AvailableMfaMethod> availableMethods = buildAvailableMethods(nextStep, user);
                    String primaryMethod = pickPrimaryMethod(availableMethods, user.getPreferred2faMethod());

                    String sessionToken = UUID.randomUUID().toString().replace("-", "");
                    MfaSession mfaSession = MfaSession.builder()
                        .sessionToken(sessionToken)
                        .userId(user.getId())
                        .tenantId(user.getTenant().getId())
                        .flowId(flow.getId())
                        .currentStep(2)  // step 1 (PASSWORD) already done
                        .totalSteps(flow.getStepCount())
                        .stepsData("[\"PASSWORD\"]")  // track by AuthMethodType for reuse check; AMR mapped at token issuance
                        .ipAddress(command.getIpAddress())
                        .userAgent(command.getUserAgent())
                        // Bind this MFA session to the OAuth2 client_id when the hosted
                        // login initiated the flow — enforced at /oauth2/authorize/complete
                        // to prevent cross-client authorization-code replay within a tenant.
                        .clientId(command.getClientId())
                        .expiresAt(Instant.now().plus(MFA_SESSION_TTL))
                        .build();
                    mfaSessionRepository.save(mfaSession);

                    log.info("AUDIT: MFA required — userId={}, remainingSteps={}, nextStepType={}, availableMethods={}, ip={}",
                        user.getId(), remainingSteps.size(), nextStep.getStepType(), availableMethods.size(), command.getIpAddress());

                    // Return MFA pending response — NO accessToken, NO refreshToken.
                    // Echo completed methods sourced from the MfaSession so the response
                    // always reflects stored state (if the session ever records multiple
                    // methods at create-time in the future, the response stays in sync).
                    return AuthenticationResponse.ofMfaPending(
                        sessionToken, flow.getStepCount(), 2, primaryMethod, availableMethods, userResponse,
                        mfaSession.getCompletedMethods()
                    );
                }
            }
        } catch (NeedsEnrollmentException e) {
            // Propagate dead-end detection to the client (login edge case #5).
            // We deliberately let this bubble past the generic catch so the
            // GlobalExceptionHandler can render a structured 400 with method +
            // enrollmentUrl. The password has been verified at this point so
            // re-auth is not required, but we DO NOT issue a token.
            log.warn("AUDIT: Login blocked — user {} cannot complete flow (needs {} enrollment)",
                    user.getId(), e.getMethod());
            auditLogPort.logAuthenticationFailed(command.getEmail(), command.getIpAddress(),
                    "needs_enrollment:" + e.getMethod());
            throw e;
        } catch (Exception e) {
            log.warn("Failed to check tenant auth flow for user {}: {}", user.getId(), e.getMessage(), e);
        }

        // No MFA required — single-factor login, issue JWT immediately
        String accessToken = tokenGenerator.generateAccessToken(user.getEmail(), List.of("pwd"));
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
            user, command.getIpAddress(), command.getUserAgent()
        );

        return AuthenticationResponse.of(accessToken, refreshToken.getToken(), tokenGenerator.getExpirationMillis(), userResponse);
    }

    /**
     * Builds the list of available MFA methods for a step, filtered by validated enrollments.
     * Uses EnrollmentHealthService to verify backing data actually exists.
     */
    private List<AvailableMfaMethod> buildAvailableMethods(AuthFlowStep step, User user) {
        List<AuthMethod> methods = step.getAvailableMethods();

        // Validate enrollments against actual backing data (auto-revokes stale ones)
        Map<AuthMethodType, Boolean> healthStatus = enrollmentHealthService.validateEnrollments(user.getId());

        String preferred = user.getPreferred2faMethod();

        return methods.stream()
            .filter(Objects::nonNull)
            .map(m -> AvailableMfaMethod.builder()
                .methodType(m.getType().name())
                .name(m.getName())
                .category(m.getCategory().name())
                .enrolled(Boolean.TRUE.equals(healthStatus.get(m.getType())) || !m.isRequiresEnrollment())
                .preferred(m.getType().name().equals(preferred))
                .requiresEnrollment(m.isRequiresEnrollment())
                .build())
            .collect(Collectors.toList());
    }

    /**
     * Returns true if the step has at least one enrollment-requiring method
     * that the user is actually enrolled in. Used to skip optional steps when
     * the user hasn't set up any biometric/hardware MFA for that step yet.
     */
    private boolean stepHasBiometricEnrollment(AuthFlowStep step, Map<AuthMethodType, Boolean> healthStatus) {
        return step.getAvailableMethods().stream()
            .filter(Objects::nonNull)
            .filter(AuthMethod::isRequiresEnrollment)
            .anyMatch(m -> Boolean.TRUE.equals(healthStatus.get(m.getType())));
    }

    /**
     * Post-audit 2026-04-24 login edge case #5.
     *
     * <p>Iterates the remaining flow steps and ensures each REQUIRED step has
     * at least one enrolled, usable method (either the primary/alternatives OR
     * a configured fallback). Throws {@link NeedsEnrollmentException} on the
     * first dead-end found — the client can then route the user to the named
     * enrollment URL before retrying login.
     *
     * <p>A step is satisfied if:
     * <ol>
     *   <li>It is not required (optional step, can be skipped),
     *   <li>OR any of its available methods is enrolled by the user
     *       (or does not require enrollment in the first place, e.g. PASSWORD,
     *       QR_CODE once we're past step-0),
     *   <li>OR its configured {@code fallbackMethod} is enrolled.
     * </ol>
     */
    private void verifyUserCanCompleteFlow(User user, List<AuthFlowStep> remainingSteps) {
        Map<AuthMethodType, Boolean> healthStatus =
                enrollmentHealthService.validateEnrollments(user.getId());

        for (AuthFlowStep step : remainingSteps) {
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
                // Fallback covers the gap — the MFA flow will route through it.
                continue;
            }

            // Pick the first NOT-usable method to report as the enrollment target.
            // CHOICE steps report the primary available method (first non-null
            // entry). Consumers render "enroll $method to continue".
            AuthMethodType missing = step.getAvailableMethods().stream()
                    .filter(Objects::nonNull)
                    .map(AuthMethod::getType)
                    .findFirst()
                    .orElse(fallback != null ? fallback.getType() : null);

            String methodName = missing != null ? missing.name() : "UNKNOWN";
            String enrollmentUrl = missing != null
                    ? "/enroll/" + missing.name().toLowerCase(java.util.Locale.ROOT)
                    : "/enroll";
            throw new NeedsEnrollmentException(methodName, enrollmentUrl);
        }
    }

    /**
     * A method is usable if it either does not require enrollment, or the user
     * is enrolled according to {@link EnrollmentHealthService}.
     */
    private boolean isMethodUsable(AuthMethod method, Map<AuthMethodType, Boolean> healthStatus) {
        if (method == null || method.getType() == null) {
            return false;
        }
        if (!method.isRequiresEnrollment()) {
            return true;
        }
        return Boolean.TRUE.equals(healthStatus.get(method.getType()));
    }

    /**
     * Picks the primary method: user's preferred (if enrolled) → first enrolled → fallback to EMAIL_OTP.
     */
    private String pickPrimaryMethod(List<AvailableMfaMethod> methods, String preferred) {
        // Try user's preferred method first
        if (preferred != null) {
            Optional<AvailableMfaMethod> pref = methods.stream()
                .filter(m -> m.getMethodType().equals(preferred) && m.isEnrolled())
                .findFirst();
            if (pref.isPresent()) return pref.get().getMethodType();
        }
        // Fall back to first enrolled method
        return methods.stream()
            .filter(AvailableMfaMethod::isEnrolled)
            .map(AvailableMfaMethod::getMethodType)
            .findFirst()
            .orElse("EMAIL_OTP");
    }
}
