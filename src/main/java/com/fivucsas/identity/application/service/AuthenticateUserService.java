package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.AuthenticateUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.AccountLockedException;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.NeedsEnrollmentException;
import com.fivucsas.identity.domain.exception.TenantMismatchException;
import com.fivucsas.identity.domain.exception.TenantSuspendedException;
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
    private final ConfigDrivenLoginPolicy configDrivenLoginPolicy;
    private final com.fivucsas.identity.application.service.mfa.AvailableMethodsResolver availableMethodsResolver;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    private static final Duration MFA_SESSION_TTL = Duration.ofMinutes(10);

    @Override
    @Transactional
    public AuthenticationResponse execute(AuthenticateUserCommand command) {
        log.info("AUDIT: Login attempt — email={}, ip={}", command.getEmail(), command.getIpAddress());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(InvalidCredentialsException::new);

        // P0-#8 (INVESTIGATION_MASTER_2026-05-07): refuse authentication when
        // the user's tenant is not ACTIVE. Tenant.canAcceptUsers() existed in
        // the domain model with zero non-DTO callers — suspended /
        // inactive / pending tenants kept minting JWTs through this path.
        // Reject AFTER the email is found (no enumeration leak: the tenant
        // identity is not exposed in the response — only the suspension fact)
        // and BEFORE the lockout / password / MFA branches so the gate
        // applies uniformly to all auth strategies.
        if (user.getTenant() != null
                && user.getTenant().getStatus() != TenantStatus.ACTIVE) {
            log.warn("AUDIT: Login refused — tenant not active, email={}, tenantId={}, tenantStatus={}, ip={}",
                    command.getEmail(), user.getTenant().getId(),
                    user.getTenant().getStatus(), command.getIpAddress());
            auditLogPort.logAuthenticationFailed(command.getEmail(),
                    command.getIpAddress(),
                    "Tenant " + user.getTenant().getStatus() + " — auth refused");
            throw new TenantSuspendedException(user.getTenant().getStatus());
        }

        // Check if account is locked
        if (user.isLocked()) {
            // Cache lockedUntil in a local so this branch makes only ONE
            // entity.User.getLockedUntil() call site — preserves the existing
            // ArchUnit FreezingArchRule baseline (UserDomainBoundaryTest) that
            // pins entity-User invocations by (caller, callee) tuple.
            Instant lockedUntil = user.getLockedUntil();
            if (lockedUntil != null && Instant.now().isAfter(lockedUntil)) {
                // Lock period expired, auto-unlock
                user.resetFailedLoginAttempts();
                userRepository.save(user);
                log.info("Account auto-unlocked after lockout period for user: {}", command.getEmail());
            } else {
                log.warn("AUDIT: Login failed — email={}, reason: account_locked, ip={}", command.getEmail(), command.getIpAddress());
                auditLogPort.logAuthenticationFailed(command.getEmail(), command.getIpAddress(), "Account locked");
                // P0-#5 (INVESTIGATION_MASTER_2026-05-07): surface a dedicated
                // AccountLockedException carrying the remaining-seconds value so
                // GlobalExceptionHandler can return HTTP 423 with a structured
                // body. Previously this path threw InvalidCredentialsException
                // and the frontend's i18n key `errors.ACCOUNT_LOCKED` was dead.
                long remainingSeconds = lockedUntil != null
                        ? Math.max(0L, Duration.between(Instant.now(), lockedUntil).getSeconds())
                        : 0L;
                throw new AccountLockedException(remainingSeconds);
            }
        }

        // Tenant lock — when the login originates from an OAuth client that is
        // bound to a specific tenant (e.g. demo.fivucsas.com → marmara-bys-demo
        // → Marmara University), refuse the login if the user belongs to a
        // different tenant. Without this gate any user from any tenant could
        // sign in on a tenant-branded surface (the user reported logging into
        // demo.fivucsas.com with their Fivucsas-tenant account on 2026-04-28).
        // Reject BEFORE the password check so the user gets a clear inline
        // error at the password step — instead of passing password + MFA only
        // to fail at /oauth2/authorize/complete with no enrollment in the
        // foreign tenant.
        //
        // 2026-05-07 (T-TENANT-GATE): switched from InvalidCredentialsException
        // (which made the password step look like a wrong-password retry loop)
        // to a dedicated TenantMismatchException carrying the required-tenant
        // display name so the frontend can render
        // "This account is not a {{tenant}} member." inline. The tenant
        // identity is already known to the user (they're on the tenant's own
        // hosted login surface) so there is no enumeration leak.
        enforceTenantLock(user, command.getClientId(), command.getEmail(), command.getIpAddress());

        // Resolve the tenant's configured Layer-1 (step-order 1) method for the
        // default APP_LOGIN flow. Task #16 B: login is now fully config-driven —
        // we no longer hard-gate every login on a password check. Instead we run
        // whatever the tenant configured as Layer-1:
        //   * PASSWORD            → verify it here as step 1 (observable behavior
        //                           is UNCHANGED for today's PASSWORD-first
        //                           tenants — same lockout, audit, MFA-pending
        //                           shape), then continue to the remaining steps.
        //   * any other method    → an identifier-first factor (EMAIL_OTP / FACE /
        //                           TOTP / …). We do NOT check the password; the
        //                           MfaSession starts at step 1 with that method
        //                           and VerifyMfaStepService runs it generically.
        // A null/empty flow (or a flow with no step 1) falls back to PASSWORD so
        // tenants without a configured flow keep the legacy password login.
        //
        // REVERSIBILITY GATE (operator directive 2026-05-30): the config-driven
        // engine is OFF by default. When OFF for this tenant we resolve NO
        // Layer-1 methods → layer1IsPassword=true → the hard password gate +
        // legacy step-2/["PASSWORD"] flow below run EXACTLY as before. Flip
        // app.auth.config-driven-login (or canary a tenant) to enable the new
        // model with no redeploy.
        boolean configDriven = user.getTenant() != null
                && configDrivenLoginPolicy.isEnabledFor(user.getTenant().getId());
        Set<AuthMethodType> layer1Methods = configDriven
                ? resolveLayer1Methods(user)
                : Set.of();
        boolean layer1IsPassword = layer1Methods.isEmpty()
                || layer1Methods.contains(AuthMethodType.PASSWORD);

        if (layer1IsPassword && !passwordEncoder.matches(command.getPassword(), user.getPasswordHash())) {
            // Increment failed attempts and potentially lock account
            user.incrementFailedLoginAttempts();
            boolean justLocked = false;
            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.lockAccount(LOCKOUT_DURATION);
                justLocked = true;
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
            // P0-#5: when this very attempt triggered the lockout, surface
            // AccountLockedException so the user gets the lockout message
            // instead of "invalid credentials" on the 5th wrong-password try.
            if (justLocked) {
                // Cache lockedUntil — single call site keeps the ArchUnit
                // FreezingArchRule baseline (UserDomainBoundaryTest) green.
                Instant lockedUntil = user.getLockedUntil();
                long remainingSeconds = lockedUntil != null
                        ? Math.max(0L, Duration.between(Instant.now(), lockedUntil).getSeconds())
                        : LOCKOUT_DURATION.getSeconds();
                throw new AccountLockedException(remainingSeconds);
            }
            throw new InvalidCredentialsException();
        }

        // Successful login — reset failed attempts and record login metadata
        if (user.getFailedLoginAttempts() > 0) {
            user.resetFailedLoginAttempts();
        }
        user.recordLogin(command.getIpAddress());

        log.info("AUDIT: User authenticated — layer1: {}, userId={}, ip={}, userAgent={}",
                layer1IsPassword ? "PASSWORD" : layer1Methods,
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

        // Drive the rest of login from the tenant's configured default APP_LOGIN
        // flow. When Layer-1 is PASSWORD it was already verified above, so the
        // "remaining" steps are step-order > 1 and the session starts at step 2
        // with PASSWORD pre-credited (legacy behavior, byte-for-byte). When
        // Layer-1 is an identifier-first method (EMAIL_OTP / FACE / TOTP / …) no
        // password was checked: ALL steps remain, the session starts at step 1
        // with no completed methods, and VerifyMfaStepService runs the Layer-1
        // method as the first step.
        try {
            Optional<AuthFlow> defaultLoginFlow = authFlowRepository
                .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                    user.getTenant().getId(), OperationType.APP_LOGIN);

            if (defaultLoginFlow.isPresent()) {
                AuthFlow flow = defaultLoginFlow.get();

                // First flow step we still need to run. PASSWORD Layer-1 already
                // satisfied step 1 ⇒ start from step 2; any other Layer-1 ⇒ start
                // from step 1 (its own step).
                int startStep = layer1IsPassword ? 2 : 1;

                // Optional steps are skipped when the user has no enrollment in any
                // enrollment-requiring method for that step — avoids forcing repeated
                // EMAIL_OTP loops on users who haven't set up biometric MFA yet.
                Map<AuthMethodType, Boolean> healthStatus =
                    enrollmentHealthService.validateEnrollments(user.getId());

                List<AuthFlowStep> remainingSteps = flow.getSteps().stream()
                    .filter(step -> step.getStepOrder() >= startStep)
                    .sorted(Comparator.comparingInt(AuthFlowStep::getStepOrder))
                    .filter(step -> step.isRequired() || stepHasBiometricEnrollment(step, healthStatus))
                    .toList();

                if (!remainingSteps.isEmpty()) {
                    // Post-audit 2026-04-24 login edge case #5 — dead-end prevention.
                    // Before committing the user to a multi-step flow, verify every
                    // REQUIRED step has either a method the user is enrolled in or
                    // a configured fallback. Otherwise we would authenticate Layer-1
                    // and then strand them mid-flow with no way to proceed.
                    // A usernameless Layer-1 step (PASSKEY/APPROVE_LOGIN/QR_CODE)
                    // proves its own enrollment by being completed, so it is exempt
                    // from the prior-enrollment requirement (task #16 F).
                    verifyUserCanCompleteFlow(user, remainingSteps);

                    // MFA required — DO NOT issue JWT yet. Only create MFA session.
                    AuthFlowStep nextStep = remainingSteps.get(0);
                    List<AvailableMfaMethod> availableMethods = buildAvailableMethods(nextStep, user);
                    String primaryMethod = pickPrimaryMethod(availableMethods, user.getPreferred2faMethod());

                    // stepsData credits PASSWORD only when it was the verified
                    // Layer-1 — an identifier-first Layer-1 has nothing completed
                    // yet (its own step is the first one to run).
                    String stepsData = layer1IsPassword ? "[\"PASSWORD\"]" : "[]";

                    String sessionToken = UUID.randomUUID().toString().replace("-", "");
                    MfaSession mfaSession = MfaSession.builder()
                        .sessionToken(sessionToken)
                        .userId(user.getId())
                        .tenantId(user.getTenant().getId())
                        .flowId(flow.getId())
                        .currentStep(startStep)
                        .totalSteps(flow.getStepCount())
                        .stepsData(stepsData)  // track by AuthMethodType for reuse check; AMR mapped at token issuance
                        .ipAddress(command.getIpAddress())
                        .userAgent(command.getUserAgent())
                        // Bind this MFA session to the OAuth2 client_id when the hosted
                        // login initiated the flow — enforced at /oauth2/authorize/complete
                        // to prevent cross-client authorization-code replay within a tenant.
                        .clientId(command.getClientId())
                        .expiresAt(Instant.now().plus(MFA_SESSION_TTL))
                        .build();
                    mfaSessionRepository.save(mfaSession);

                    log.info("AUDIT: MFA required — userId={}, startStep={}, remainingSteps={}, nextStepType={}, availableMethods={}, ip={}",
                        user.getId(), startStep, remainingSteps.size(), nextStep.getStepType(), availableMethods.size(), command.getIpAddress());

                    // Return MFA pending response — NO accessToken, NO refreshToken.
                    // Echo completed methods sourced from the MfaSession so the response
                    // always reflects stored state (if the session ever records multiple
                    // methods at create-time in the future, the response stays in sync).
                    return AuthenticationResponse.ofMfaPending(
                        sessionToken, flow.getStepCount(), startStep, primaryMethod, availableMethods, userResponse,
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

        // No MFA required — single-factor login, issue JWT immediately. The amr
        // reflects the verified Layer-1 factor: "pwd" for a PASSWORD Layer-1
        // (the only single-step case in practice — an identifier-first Layer-1
        // always contributes its own runnable step and goes through MFA-pending).
        List<String> amr = layer1IsPassword ? List.of("pwd") : amrFor(layer1Methods);
        String accessToken = tokenGenerator.generateAccessToken(user.getEmail(), amr);
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
        // Delegate to the single shared resolver so EVERY login layer uses the same
        // enrolled rule (incl. PASSWORD-by-password-hash). See AvailableMethodsResolver.
        Map<AuthMethodType, Boolean> healthStatus = enrollmentHealthService.validateEnrollments(user.getId());
        return availableMethodsResolver.build(
                step,
                com.fivucsas.identity.application.service.mfa.AvailableMethodsResolver.hasPassword(user.getPasswordHash()),
                healthStatus,
                user.getPreferred2faMethod());
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
     * A method is usable if it either does not require enrollment, is a
     * usernameless factor (PASSKEY/APPROVE_LOGIN/QR_CODE — the factor proves its
     * own enrollment by being completed, so no prior enrollment row is required
     * to start the flow; task #16 F), or the user is enrolled according to
     * {@link EnrollmentHealthService}.
     */
    private boolean isMethodUsable(AuthMethod method, Map<AuthMethodType, Boolean> healthStatus) {
        if (method == null || method.getType() == null) {
            return false;
        }
        if (!method.isRequiresEnrollment() || method.isSupportsUsernameless()) {
            return true;
        }
        return Boolean.TRUE.equals(healthStatus.get(method.getType()));
    }

    /**
     * Resolves the set of {@link AuthMethodType}s configured for step-order 1
     * (Layer-1) of the tenant's default APP_LOGIN flow. Returns an empty set
     * when the tenant has no default flow / no step 1, in which case the caller
     * falls back to the legacy PASSWORD login.
     *
     * <p>For a SEQUENTIAL step this is a single method; for a CHOICE step it is
     * the set of alternatives. Layer-1 is treated as PASSWORD-first (the legacy
     * path) whenever PASSWORD is one of those options — the user supplies the
     * password they already typed, and any other option is offered as a later
     * step or a CHOICE the MFA engine handles.
     */
    private Set<AuthMethodType> resolveLayer1Methods(User user) {
        try {
            if (user.getTenant() == null) {
                return Set.of();
            }
            Optional<AuthFlow> defaultLoginFlow = authFlowRepository
                .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                    user.getTenant().getId(), OperationType.APP_LOGIN);
            if (defaultLoginFlow.isEmpty()) {
                return Set.of();
            }
            return defaultLoginFlow.get().getSteps().stream()
                .filter(s -> s.getStepOrder() == 1)
                .findFirst()
                .map(s -> s.getAvailableMethods().stream()
                        .filter(Objects::nonNull)
                        .map(AuthMethod::getType)
                        .collect(Collectors.toCollection(java.util.LinkedHashSet::new)))
                .map(set -> (Set<AuthMethodType>) set)
                .orElseGet(Set::of);
        } catch (Exception e) {
            // Any lookup failure falls back to legacy PASSWORD login rather than
            // locking everyone out of a misconfigured tenant.
            log.warn("Failed to resolve Layer-1 methods for user {}: {} — defaulting to PASSWORD",
                    user.getId(), e.getMessage());
            return Set.of();
        }
    }

    /** RFC 8176 amr values for a single-step identifier-first Layer-1 mint. */
    private List<String> amrFor(Set<AuthMethodType> methods) {
        return methods.stream()
                .map(AuthenticateUserService::amrValue)
                .distinct()
                .toList();
    }

    private static String amrValue(AuthMethodType type) {
        return switch (type) {
            case PASSWORD -> "pwd";
            case EMAIL_OTP, SMS_OTP, TOTP -> "otp";
            case FACE -> "face";
            case VOICE -> "voice";
            case FINGERPRINT -> "fpt";
            case HARDWARE_KEY, PASSKEY -> "hwk";
            case QR_CODE, APPROVE_LOGIN -> "mca";
            case NFC_DOCUMENT -> "swk";
            default -> type.name().toLowerCase(java.util.Locale.ROOT);
        };
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

    /**
     * Tenant lock — when the login originates from an OAuth client bound to a
     * specific tenant (e.g. demo.fivucsas.com → marmara-bys-demo → Marmara), refuse
     * the login if the user belongs to a DIFFERENT tenant. Throws
     * {@link TenantMismatchException} (→ HTTP 403 + errorCode TENANT_MISMATCH +
     * required-tenant display name). System-tenant clients are intentionally
     * cross-tenant (e.g. the dashboard) and are NOT gated. Extracted so the
     * password login path AND the identifier-first pre-flight share one
     * implementation. Non-mismatch failures are swallowed (fail-open to the
     * regular login path), exactly as the inline gate behaved before extraction.
     */
    private void enforceTenantLock(User user, String clientId, String email, String ipAddress) {
        if (clientId == null || clientId.isBlank()) {
            return;
        }
        try {
            Optional<OAuth2Client> tenantBoundClient = oAuth2ClientRepository.findByClientId(clientId);
            if (tenantBoundClient.isPresent() && tenantBoundClient.get().getTenant() != null) {
                UUID clientTenantId = tenantBoundClient.get().getTenant().getId();
                UUID systemTenantId = UUID.fromString("00000000-0000-0000-0000-000000000000");
                // Only enforce on tenant-scoped clients (system-tenant clients are
                // intentionally cross-tenant — e.g. fivucsas-web-dashboard).
                if (clientTenantId != null
                        && !clientTenantId.equals(systemTenantId)
                        && user.getTenant() != null
                        && !clientTenantId.equals(user.getTenant().getId())) {
                    String requiredTenantName = tenantBoundClient.get().getTenant().getName();
                    if (requiredTenantName == null || requiredTenantName.isBlank()) {
                        // Fall back to the client's display name, then to client_id.
                        requiredTenantName = tenantBoundClient.get().getClientName();
                    }
                    if (requiredTenantName == null || requiredTenantName.isBlank()) {
                        requiredTenantName = clientId;
                    }
                    log.warn("AUDIT: Login refused — tenant mismatch, email={}, " +
                                    "userTenant={}, clientTenant={}, clientId={}, ip={}",
                            email, user.getTenant().getId(), clientTenantId, clientId, ipAddress);
                    auditLogPort.logAuthenticationFailed(email, ipAddress,
                            "Tenant mismatch for OAuth client " + clientId);
                    throw new TenantMismatchException(requiredTenantName);
                }
            }
        } catch (TenantMismatchException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Tenant-lock check failed for client '{}': {}", clientId, e.getMessage());
        }
    }

    /**
     * Identifier-first pre-flight: given an email + tenant-bound clientId, throw
     * {@link TenantMismatchException} if that email belongs to a DIFFERENT tenant —
     * WITHOUT verifying any password. Lets the hosted login surface the
     * "not a {tenant} member" error on the identity (email) step instead of one
     * step later at the password step. No password is checked and no lockout
     * counter is touched. An unknown email is a silent no-op (the password step
     * then returns the normal invalid-credentials response), so this is no more of
     * an enumeration oracle than the existing password-step gate.
     */
    @Override
    @Transactional(readOnly = true)
    public void checkTenantEligibility(String email, String clientId) {
        if (email == null || email.isBlank()) {
            return;
        }
        userRepository.findByEmail(email)
                .ifPresent(user -> enforceTenantLock(user, clientId, email, null));
    }

    @Override
    @Transactional(readOnly = true)
    public UUID resolveHomeTenantId(String email) {
        if (email == null || email.isBlank()) {
            return null;
        }
        return userRepository.findByEmail(email)
                .map(user -> user.getTenant() != null ? user.getTenant().getId() : null)
                .orElse(null);
    }

    @Override
    @Transactional
    public AuthenticationResponse beginIdentifierLogin(String email, String clientId, String ipAddress, String userAgent) {
        Optional<User> userOpt = (email == null || email.isBlank())
                ? Optional.empty()
                : userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return decoyBeginResponse();
        }
        User user = userOpt.get();

        // Tenant-lock (hosted surface bound to a tenant) — 403 on mismatch, same
        // as the password path, so the email step shows "not a {tenant} member".
        enforceTenantLock(user, clientId, email, ipAddress);

        // Arbitrary-first-factor is part of the config-driven engine. When OFF for
        // the tenant (or no default flow), there is no password-less entry — return
        // a decoy so the surface is indistinguishable from an unknown identifier.
        boolean configDriven = user.getTenant() != null
                && configDrivenLoginPolicy.isEnabledFor(user.getTenant().getId());
        Optional<AuthFlow> defaultLoginFlow = !configDriven
                ? Optional.empty()
                : authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                        user.getTenant().getId(), OperationType.APP_LOGIN);
        if (defaultLoginFlow.isEmpty()) {
            return decoyBeginResponse();
        }
        AuthFlow flow = defaultLoginFlow.get();

        // The steps the user will actually face (step 1 onward). Optional steps the
        // user can't satisfy are skipped; required ones are dead-end-checked below.
        Map<AuthMethodType, Boolean> healthStatus = enrollmentHealthService.validateEnrollments(user.getId());
        List<AuthFlowStep> steps = flow.getSteps().stream()
                .sorted(Comparator.comparingInt(AuthFlowStep::getStepOrder))
                .filter(step -> step.getStepOrder() == 1 || step.isRequired()
                        || stepHasBiometricEnrollment(step, healthStatus))
                .toList();
        AuthFlowStep step1 = steps.stream()
                .filter(s -> s.getStepOrder() == 1)
                .findFirst()
                .orElse(null);
        if (step1 == null) {
            return decoyBeginResponse();
        }

        // Dead-end guard (login edge case #5): bubbles NeedsEnrollmentException so
        // the client routes the user to enroll instead of stranding them mid-flow.
        verifyUserCanCompleteFlow(user, steps);

        List<AvailableMfaMethod> availableMethods = buildAvailableMethods(step1, user);
        String primaryMethod = pickPrimaryMethod(availableMethods, user.getPreferred2faMethod());

        String sessionToken = UUID.randomUUID().toString().replace("-", "");
        MfaSession mfaSession = MfaSession.builder()
                .sessionToken(sessionToken)
                .userId(user.getId())
                .tenantId(user.getTenant().getId())
                .flowId(flow.getId())
                .currentStep(1)               // run the chosen Layer-1 method as step 1
                .totalSteps(flow.getStepCount())
                .stepsData("[]")              // nothing satisfied yet — no password pre-credit
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .clientId(clientId)
                .expiresAt(Instant.now().plus(MFA_SESSION_TTL))
                .build();
        mfaSessionRepository.save(mfaSession);

        log.info("AUDIT: identifier-first begin — userId={}, layer1Options={}, totalSteps={}, ip={}",
                user.getId(), availableMethods.size(), flow.getStepCount(), ipAddress);

        // user=null: no profile is exposed before any factor is proven (the password
        // path returns the user only AFTER the password is verified). Enumeration-safe.
        return AuthenticationResponse.ofMfaPending(
                sessionToken, flow.getStepCount(), 1, primaryMethod, availableMethods, null, List.of());
    }

    /**
     * Enumeration-safe decoy for {@link #beginIdentifierLogin}: an MFA-pending
     * shape with a random token that maps to NO persisted {@link MfaSession}, so
     * any {@code /auth/mfa/step} submission returns "invalid/expired session".
     *
     * <p>A decoy is necessarily SYNTHETIC — an unknown identifier resolves to no
     * user → no tenant → no flow to read, and deriving the shape from anything
     * real would itself be the enumeration leak. To avoid inventing a second
     * "default" we mirror the SINGLE platform-default baseline that
     * {@code /auth/login/preflight} and {@code LoginConfigService.passwordFirstConfig}
     * already present for an unresolved surface: PASSWORD-only, one step. So
     * begin/preflight stay consistent and an unknown email looks exactly like a
     * tenant whose Layer-1 is a lone password. Mirrors {@code ApproveLoginService}.
     */
    private AuthenticationResponse decoyBeginResponse() {
        String token = UUID.randomUUID().toString().replace("-", "");
        List<AvailableMfaMethod> platformDefault = List.of(
                AvailableMfaMethod.builder()
                        .methodType(AuthMethodType.PASSWORD.name())
                        .name("Password")
                        .category(com.fivucsas.identity.domain.model.auth.AuthMethodCategory.BASIC.name())
                        .enrolled(true)
                        .preferred(true)
                        .requiresEnrollment(false)
                        .build());
        return AuthenticationResponse.ofMfaPending(
                token, 1, 1, AuthMethodType.PASSWORD.name(), platformDefault, null, List.of());
    }
}
