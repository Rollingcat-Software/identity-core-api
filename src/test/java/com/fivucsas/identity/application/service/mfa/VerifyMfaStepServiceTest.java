package com.fivucsas.identity.application.service.mfa;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.application.service.EnrollmentHealthService;
import com.fivucsas.identity.domain.exception.OtpAttemptsExhaustedException;
import com.fivucsas.identity.domain.model.auth.AuthMethodCategory;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.auth.StepType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Service-level tests for {@link VerifyMfaStepService}, the orchestrator
 * extracted from {@code AuthController.verifyMfaStep} during the P2.9
 * refactor.
 *
 * <p>Coverage:
 * <ul>
 *   <li>Per-method handler dispatch — 4 representative methods (PASSWORD,
 *       TOTP, FACE, HARDWARE_KEY) verify the orchestrator routes to the
 *       correct handler and surfaces its result.</li>
 *   <li>Final-step completion mints access + refresh tokens and emits the
 *       MFA_COMPLETE audit event with the accumulated RFC 8176 {@code amr}
 *       claim.</li>
 *   <li>Mid-flow step advancement emits MFA_STEP_COMPLETED audit and saves
 *       the session without minting tokens.</li>
 *   <li>Failure path emits MFA_STEP_FAILED audit (ported from legacy
 *       AuthControllerTest).</li>
 *   <li>Substitution-guard logic (METHOD_ALREADY_USED) — ports the three
 *       legacy AuthControllerTest cases that were disabled when the
 *       business logic moved here:
 *       (1) retrying the same method on the same step is allowed;
 *       (2) submitting a previously-completed method at a step whose
 *           configured method differs is rejected;
 *       (3) submitting a previously-completed method at a step whose
 *           configured method matches is allowed (legitimate repeat).</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class VerifyMfaStepServiceTest {

    @Mock private MfaSessionRepository mfaSessionRepository;
    @Mock private UserRepository userRepository;
    @Mock private AuthFlowRepositoryPort authFlowRepository;
    @Mock private EnrollmentHealthService enrollmentHealthService;
    @Mock private TokenGenerationPort tokenGenerator;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private AuditLogPort auditLogPort;

    @Mock private VerifyMfaStepHandler passwordHandler;
    @Mock private VerifyMfaStepHandler totpHandler;
    @Mock private VerifyMfaStepHandler faceHandler;
    @Mock private VerifyMfaStepHandler hardwareKeyHandler;
    @Mock private VerifyMfaStepHandler emailOtpHandler;

    private VerifyMfaStepService service;

    private static final String SESSION_TOKEN = "test-session-token";
    private static final String CLIENT_IP = "10.0.0.1";
    private static final String UA = "test-agent/1.0";

    @BeforeEach
    void setUp() {
        // Stub the supports() of every handler so the service's constructor
        // (which builds an EnumMap) can register them. lenient() because not
        // every test uses every handler.
        lenient().when(passwordHandler.supports()).thenReturn(AuthMethodType.PASSWORD);
        lenient().when(totpHandler.supports()).thenReturn(AuthMethodType.TOTP);
        lenient().when(faceHandler.supports()).thenReturn(AuthMethodType.FACE);
        lenient().when(hardwareKeyHandler.supports()).thenReturn(AuthMethodType.HARDWARE_KEY);
        lenient().when(emailOtpHandler.supports()).thenReturn(AuthMethodType.EMAIL_OTP);

        service = new VerifyMfaStepService(
                List.of(passwordHandler, totpHandler, faceHandler, hardwareKeyHandler, emailOtpHandler),
                mfaSessionRepository, userRepository, authFlowRepository,
                enrollmentHealthService, tokenGenerator, refreshTokenService, auditLogPort);
    }

    // ============== Handler dispatch — 4 representative methods ==============

    @Test
    void dispatchesToPasswordHandler() {
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 1, 2, "[]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.PASSWORD),
                stepOf(2, AuthMethodType.EMAIL_OTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(passwordHandler.verify(eq(session), eq(user), any())).thenReturn(MfaStepResult.ok());
        when(mfaSessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(enrollmentHealthService.validateEnrollments(any())).thenReturn(Map.of());

        VerifyMfaStepResponse result = service.execute(req("PASSWORD",
                Map.of("password", "secret")));

        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.OK);
        verify(passwordHandler).verify(eq(session), eq(user), any());
        verify(totpHandler, never()).verify(any(), any(), any());
        verify(faceHandler, never()).verify(any(), any(), any());
        verify(hardwareKeyHandler, never()).verify(any(), any(), any());
    }

    @Test
    void dispatchesToTotpHandler() {
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 2, 3, "[\"PASSWORD\"]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.PASSWORD),
                stepOf(2, AuthMethodType.TOTP),
                stepOf(3, AuthMethodType.EMAIL_OTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(totpHandler.verify(eq(session), eq(user), any())).thenReturn(MfaStepResult.ok());
        when(mfaSessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(enrollmentHealthService.validateEnrollments(any())).thenReturn(Map.of());

        service.execute(req("TOTP", Map.of("code", "123456")));

        verify(totpHandler).verify(eq(session), eq(user), any());
        verify(passwordHandler, never()).verify(any(), any(), any());
    }

    @Test
    void dispatchesToFaceHandler() {
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 2, 3, "[\"PASSWORD\"]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.PASSWORD),
                stepOf(2, AuthMethodType.FACE),
                stepOf(3, AuthMethodType.EMAIL_OTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(faceHandler.verify(eq(session), eq(user), any())).thenReturn(MfaStepResult.ok());
        when(mfaSessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(enrollmentHealthService.validateEnrollments(any())).thenReturn(Map.of());

        service.execute(req("FACE", Map.of("image", "base64data")));

        verify(faceHandler).verify(eq(session), eq(user), any());
    }

    @Test
    void dispatchesToHardwareKeyHandler_andPassesChallengeThrough() {
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 1, 2, "[]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.HARDWARE_KEY),
                stepOf(2, AuthMethodType.EMAIL_OTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        // CHALLENGE response should short-circuit BEFORE the substitution guard
        // resolves the current step → no AuthFlow lookup expected on this path.
        when(hardwareKeyHandler.verify(eq(session), eq(user), any())).thenReturn(
                MfaStepResult.challenge(Map.of("status", "CHALLENGE",
                        "data", Map.of("challenge", "abc123"))));

        VerifyMfaStepResponse result = service.execute(req("HARDWARE_KEY",
                Map.of("action", "challenge")));

        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.OK);
        assertThat(result.body()).containsEntry("status", "CHALLENGE");
        verify(hardwareKeyHandler).verify(eq(session), eq(user), any());
        // Challenge path: session NOT advanced, NO audit emitted.
        verify(mfaSessionRepository, never()).save(any());
        verify(auditLogPort, never())
                .logMfaStepCompleted(anyString(), anyString(), anyInt(), anyInt(), anyString(), anyString());
    }

    // ====== OTP exhaustion must surface as 429, not be swallowed into 200 ======

    @Test
    void otpAttemptsExhausted_isRethrown_notSwallowedInto200() {
        // Regression (PR #100 review): the EMAIL_OTP handler throws
        // OtpAttemptsExhaustedException once the per-code attempt budget is
        // burned. The orchestrator MUST let it propagate (→ 429 via
        // GlobalExceptionHandler), NOT collapse it into a generic 200 ERROR.
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 1, 2, "[]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.EMAIL_OTP),
                stepOf(2, AuthMethodType.PASSWORD));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(emailOtpHandler.verify(eq(session), eq(user), any()))
                .thenThrow(new OtpAttemptsExhaustedException());

        assertThatThrownBy(() -> service.execute(req("EMAIL_OTP", Map.of("code", "000000"))))
                .isInstanceOf(OtpAttemptsExhaustedException.class);
    }

    // ============== Final-step completion ==============

    @Test
    void finalStep_mintsTokensAndAccumulatesAmr() {
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        // 2-step flow; user is on the LAST step.
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 2, 2, "[\"PASSWORD\"]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.PASSWORD),
                stepOf(2, AuthMethodType.TOTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(totpHandler.verify(eq(session), eq(user), any())).thenReturn(MfaStepResult.ok());
        when(mfaSessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        when(tokenGenerator.generateAccessToken(anyString(), any())).thenReturn("access-jwt");
        when(tokenGenerator.getExpirationMillis()).thenReturn(86400000L);
        RefreshToken refresh = org.mockito.Mockito.mock(RefreshToken.class);
        when(refresh.getToken()).thenReturn("refresh-tok");
        when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refresh);

        VerifyMfaStepResponse result = service.execute(req("TOTP", Map.of("code", "123456")));

        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.OK);
        assertThat(result.body())
                .containsEntry("status", "AUTHENTICATED")
                .containsEntry("accessToken", "access-jwt")
                .containsEntry("refreshToken", "refresh-tok")
                .containsEntry("expiresIn", 86400000L);

        // RFC 8176 amr claim: PASSWORD ("pwd") + TOTP ("otp"), in completion order.
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> amrCaptor = ArgumentCaptor.forClass(List.class);
        verify(tokenGenerator).generateAccessToken(eq(user.getEmail()), amrCaptor.capture());
        assertThat(amrCaptor.getValue()).containsExactly("pwd", "otp");

        // MFA_COMPLETE audit emitted with the same amr list.
        verify(auditLogPort).logMfaComplete(eq(userId.toString()), eq(amrCaptor.getValue()),
                eq(CLIENT_IP), eq(UA));
        // Per-step audit MUST NOT fire on the terminal step.
        verify(auditLogPort, never())
                .logMfaStepCompleted(anyString(), anyString(), anyInt(), anyInt(), anyString(), anyString());
    }

    // ============== Mid-flow advancement ==============

    @Test
    void midFlow_advancesStepAndEmitsStepCompletedAudit() {
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 1, 3, "[]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.PASSWORD),
                stepOf(2, AuthMethodType.EMAIL_OTP),
                stepOf(3, AuthMethodType.TOTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(passwordHandler.verify(eq(session), eq(user), any())).thenReturn(MfaStepResult.ok());
        when(mfaSessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(enrollmentHealthService.validateEnrollments(any())).thenReturn(Map.of());

        VerifyMfaStepResponse result = service.execute(req("PASSWORD",
                Map.of("password", "secret")));

        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.OK);
        assertThat(result.body())
                .containsEntry("status", "STEP_COMPLETED")
                .containsEntry("currentStep", 2)
                .containsEntry("totalSteps", 3);

        // Audit fired for the just-completed step (step 1 of 3).
        verify(auditLogPort).logMfaStepCompleted(eq(userId.toString()), eq("PASSWORD"),
                eq(1), eq(3), eq(CLIENT_IP), eq(UA));
        // No tokens minted mid-flow.
        verify(tokenGenerator, never()).generateAccessToken(anyString(), any());
        verify(refreshTokenService, never()).createRefreshToken(any(), any(), any());
    }

    // ============== Failure path ==============

    @Test
    void handlerFailure_emitsStepFailedAuditAndReturnsFailedStatus() {
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 2, 3, "[\"PASSWORD\"]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.PASSWORD),
                stepOf(2, AuthMethodType.EMAIL_OTP),
                stepOf(3, AuthMethodType.TOTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(emailOtpHandler.verify(eq(session), eq(user), any())).thenReturn(MfaStepResult.fail());

        VerifyMfaStepResponse result = service.execute(req("EMAIL_OTP", Map.of("code", "wrong")));

        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.OK);
        assertThat(result.body()).containsEntry("status", "FAILED");
        verify(auditLogPort).logMfaStepFailed(eq(userId.toString()), eq("EMAIL_OTP"),
                eq("invalid_or_expired_otp"), eq(CLIENT_IP), eq(UA));
        // Failed step does NOT advance session — no save expected.
        verify(mfaSessionRepository, never()).save(any());
    }

    // ============== Substitution guard — ported from legacy AuthControllerTest ==============

    @Test
    void retrySameStep_isNotRejectedAsSubstitution() {
        // Flow PASSWORD → EMAIL_OTP → TOTP, user on step 2. Wrong OTP first
        // attempt MUST return status=FAILED (not METHOD_ALREADY_USED): a
        // failed attempt does not add to completedMethods, and EMAIL_OTP IS
        // the configured method at step 2 anyway.
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 2, 3, "[\"PASSWORD\"]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.PASSWORD),
                stepOf(2, AuthMethodType.EMAIL_OTP),
                stepOf(3, AuthMethodType.TOTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(emailOtpHandler.verify(eq(session), eq(user), any())).thenReturn(MfaStepResult.fail());

        VerifyMfaStepResponse result = service.execute(req("EMAIL_OTP", Map.of("code", "000000")));

        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.OK);
        assertThat(result.body())
                .containsEntry("status", "FAILED")
                .doesNotContainKey("error");
    }

    @Test
    void substitutionAttempt_isRejected() {
        // Flow PASSWORD → EMAIL_OTP → TOTP, user on step 3 with PASSWORD and
        // EMAIL_OTP completed. Re-submitting EMAIL_OTP for step 3 (configured
        // method TOTP) MUST trip METHOD_ALREADY_USED.
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 3, 3,
                "[\"PASSWORD\",\"EMAIL_OTP\"]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.PASSWORD),
                stepOf(2, AuthMethodType.EMAIL_OTP),
                stepOf(3, AuthMethodType.TOTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));

        VerifyMfaStepResponse result = service.execute(req("EMAIL_OTP", Map.of("code", "123456")));

        // Post-audit 2026-04-24 edge case #4: substitution rejection now returns
        // 409 CONFLICT (not 400) — request is well-formed but conflicts with
        // session state, matching /mfa/switch-method's existing convention.
        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.CONFLICT);
        assertThat(result.body())
                .containsEntry("error", "METHOD_ALREADY_USED")
                // Edge case #5: recovery context is included so clients don't
                // need a follow-up GET on session state.
                .containsEntry("currentStep", 3)
                .containsEntry("totalSteps", 3)
                .containsEntry("nextAction", "SWITCH_METHOD")
                .containsKey("expectedMethods")
                .containsKey("completedMethods");
        // Guard fires BEFORE handler dispatch.
        verify(emailOtpHandler, never()).verify(any(), any(), any());
    }

    @Test
    void legitimateRepeatedMethod_isAllowed() {
        // Flow PASSWORD → EMAIL_OTP → EMAIL_OTP. User on step 3 (configured
        // method EMAIL_OTP) with PASSWORD + EMAIL_OTP previously completed.
        // The reuse guard must NOT fire because EMAIL_OTP is the expected
        // method at the current step.
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 3, 3,
                "[\"PASSWORD\",\"EMAIL_OTP\"]");
        AuthFlow flow = flowOf(flowId,
                stepOf(1, AuthMethodType.PASSWORD),
                stepOf(2, AuthMethodType.EMAIL_OTP),
                stepOf(3, AuthMethodType.EMAIL_OTP));
        User user = userMock(userId);

        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(emailOtpHandler.verify(eq(session), eq(user), any())).thenReturn(MfaStepResult.ok());
        when(mfaSessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenGenerator.generateAccessToken(anyString(), any())).thenReturn("jwt");
        when(tokenGenerator.getExpirationMillis()).thenReturn(86400000L);
        RefreshToken refresh = org.mockito.Mockito.mock(RefreshToken.class);
        when(refresh.getToken()).thenReturn("rt");
        when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refresh);

        VerifyMfaStepResponse result = service.execute(req("EMAIL_OTP", Map.of("code", "654321")));

        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.OK);
        assertThat(result.body())
                .doesNotContainKey("error")
                .containsEntry("status", "AUTHENTICATED");
        verify(emailOtpHandler).verify(eq(session), eq(user), any());
    }

    // ============== Envelope validation ==============

    @Test
    void missingSessionToken_isBadRequest() {
        VerifyMfaStepResponse result = service.execute(
                new VerifyMfaStepRequest(null, "EMAIL_OTP", Map.of(), CLIENT_IP, UA));
        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.BAD_REQUEST);
        assertThat(result.body()).containsEntry("message", "sessionToken is required");
    }

    @Test
    void missingMethod_isBadRequest() {
        VerifyMfaStepResponse result = service.execute(
                new VerifyMfaStepRequest(SESSION_TOKEN, null, Map.of(), CLIENT_IP, UA));
        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.BAD_REQUEST);
        assertThat(result.body()).containsEntry("message", "method is required");
    }

    @Test
    void unknownMethod_isBadRequest() {
        UUID userId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        MfaSession session = mfaSessionAt(SESSION_TOKEN, userId, flowId, 1, 2, "[]");
        User user = userMock(userId);
        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.of(session));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        VerifyMfaStepResponse result = service.execute(req("BOGUS_METHOD", Map.of()));
        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.BAD_REQUEST);
        assertThat(result.body().get("message").toString()).contains("Unknown auth method");
    }

    @Test
    void unknownSession_isUnauthorized() {
        when(mfaSessionRepository.findBySessionTokenForUpdate(SESSION_TOKEN))
                .thenReturn(Optional.empty());

        VerifyMfaStepResponse result = service.execute(req("EMAIL_OTP", Map.of()));
        assertThat(result.status()).isEqualTo(VerifyMfaStepResponse.Status.UNAUTHORIZED);
    }

    @Test
    void registeredHandlerCount_matchesInjectedHandlers() {
        // 5 handlers wired in setUp. Sanity check that constructor de-duplicates
        // by AuthMethodType — adding the same handler twice MUST raise.
        assertThat(service.registeredHandlerCount()).isEqualTo(5);
    }

    // ============== Helpers ==============

    private VerifyMfaStepRequest req(String method, Map<String, Object> data) {
        return new VerifyMfaStepRequest(SESSION_TOKEN, method, data, CLIENT_IP, UA);
    }

    private AuthMethod methodOf(AuthMethodType type) {
        return AuthMethod.builder()
                .id(UUID.randomUUID())
                .type(type)
                .name(type.name())
                .category(AuthMethodCategory.BASIC)
                .platforms(List.of("web"))
                .build();
    }

    private AuthFlowStep stepOf(int order, AuthMethodType type) {
        return AuthFlowStep.builder()
                .id(UUID.randomUUID())
                .stepOrder(order)
                .authMethod(methodOf(type))
                .stepType(StepType.SEQUENTIAL)
                .alternativeMethods(Collections.emptyList())
                .isRequired(true)
                .timeoutSeconds(120)
                .maxAttempts(3)
                .allowsDelegation(true)
                .config("{}")
                .build();
    }

    private AuthFlow flowOf(UUID flowId, AuthFlowStep... steps) {
        return AuthFlow.builder()
                .id(flowId)
                .name("Test Flow")
                .operationType(OperationType.APP_LOGIN)
                .steps(new ArrayList<>(Arrays.asList(steps)))
                .build();
    }

    private MfaSession mfaSessionAt(String sessionToken, UUID userId, UUID flowId,
                                    int currentStep, int totalSteps, String completedMethodsJson) {
        return MfaSession.builder()
                .id(UUID.randomUUID())
                .sessionToken(sessionToken)
                .userId(userId)
                .tenantId(UUID.randomUUID())
                .flowId(flowId)
                .currentStep(currentStep)
                .totalSteps(totalSteps)
                .stepsData(completedMethodsJson)
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }

    private User userMock(UUID userId) {
        User user = org.mockito.Mockito.mock(User.class);
        lenient().when(user.getId()).thenReturn(userId);
        lenient().when(user.getEmail()).thenReturn("test@fivucsas.com");
        lenient().when(user.getStatus()).thenReturn(UserStatus.ACTIVE);
        lenient().when(user.getFirstName()).thenReturn("Test");
        lenient().when(user.getLastName()).thenReturn("User");
        lenient().when(user.getCreatedAt()).thenReturn(Instant.now());
        lenient().when(user.getUpdatedAt()).thenReturn(Instant.now());
        lenient().when(user.isActive()).thenReturn(true);
        return user;
    }
}
