package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.input.AuthenticateUserUseCase;
import com.fivucsas.identity.application.port.input.GetCurrentUserUseCase;
import com.fivucsas.identity.application.port.input.LogoutUserUseCase;
import com.fivucsas.identity.application.port.input.RefreshTokenUseCase;
import com.fivucsas.identity.application.port.input.RegisterUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.application.service.EnrollmentHealthService;
import com.fivucsas.identity.application.service.PuzzleLayerPolicy;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.infrastructure.totp.TotpService;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.security.TotpSecretCipher;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Proxy-endpoint tests for the PUZZLE-as-login session proxy (CV-2):
 * {@code POST /auth/mfa/puzzle/session} (CREATE) and
 * {@code POST /auth/mfa/puzzle/session/{id}/challenge} (SUBMIT).
 *
 * <p>The security-critical assertion: CREATE stamps {@code user_id} +
 * {@code tenant_id} from the SERVER-side MFA session — a client-supplied
 * {@code user_id} in the body is IGNORED — so the issued session is owner-bound
 * to the authenticating user, not whoever the client claims to be.
 */
@WebMvcTest(controllers = AuthController.class,
        excludeAutoConfiguration = {
                org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
                org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("AuthController — PUZZLE session proxy (CREATE owner-binds to the server MFA session)")
class AuthControllerPuzzleSessionProxyTest {

    private static final String SESSION_TOKEN = "mfa-session-token-abc";
    private static final UUID SERVER_USER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final UUID SERVER_TENANT_ID = UUID.fromString("99999999-8888-7777-6666-555555555555");
    private static final UUID FLOW_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static final String BIO_SESSION_ID = "tok_opaque_server_issued";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private RegisterUserUseCase registerUserUseCase;
    @MockBean private AuthenticateUserUseCase authenticateUserUseCase;
    @MockBean private RefreshTokenUseCase refreshTokenUseCase;
    @MockBean private LogoutUserUseCase logoutUserUseCase;
    @MockBean private GetCurrentUserUseCase getCurrentUserUseCase;

    @MockBean private JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockBean private UserDetailsService userDetailsService;
    @MockBean private RateLimitService rateLimitService;

    @MockBean private TenantRepository tenantRepository;
    @MockBean private UserRepository userRepository;
    @MockBean private MfaSessionRepository mfaSessionRepository;
    @MockBean private UserEnrollmentRepository userEnrollmentRepository;

    @MockBean private OtpService otpService;
    @MockBean private EmailService emailService;
    @MockBean private SmsService smsService;
    @MockBean private PasswordEncoder passwordEncoder;
    @MockBean private CachePort cachePort;
    @MockBean private RedisConnectionFactory redisConnectionFactory;
    @MockBean private StringRedisTemplate stringRedisTemplate;
    @MockBean private EnrollmentHealthService enrollmentHealthService;
    @MockBean private NfcCardRepositoryPort nfcCardRepository;
    @MockBean private QrCodeService qrCodeService;
    @MockBean private WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;
    @MockBean private AuditLogPort auditLogPort;
    @MockBean private AuthFlowRepositoryPort authFlowRepository;
    @MockBean private TotpService totpService;
    @MockBean private BiometricServicePort biometricService;
    @MockBean private WebAuthnService webAuthnService;
    @MockBean private TokenGenerationPort tokenGenerator;
    @MockBean private RefreshTokenService refreshTokenService;
    @MockBean private TotpSecretCipher totpSecretCipher;
    @MockBean private com.fivucsas.identity.application.service.mfa.VerifyMfaStepService verifyMfaStepService;
    @MockBean private com.fivucsas.identity.application.service.LoginConfigService loginConfigService;
    @MockBean private com.fivucsas.identity.application.service.mfa.AvailableMethodsResolver availableMethodsResolver;
    @MockBean private PuzzleLayerPolicy puzzleLayerPolicy;

    @BeforeEach
    void setUp() {
        when(rateLimitService.allowLoginAttempt(anyString())).thenReturn(true);
        when(rateLimitService.allowMfaStepAttempt(anyString())).thenReturn(true);
        // Puzzle layer ON for the session tenant by default (the reachability gate).
        lenient().when(puzzleLayerPolicy.isEnabledFor(any())).thenReturn(true);
    }

    /**
     * Builds a live (not expired / not completed) MFA session bound to the server
     * identity AND registers it on the repository for {@link #SESSION_TOKEN}.
     *
     * <p>The session is fully stubbed and the {@code findBySessionToken} stub is
     * set up BEFORE returning — the mock is never created inside another mock's
     * {@code when(...).thenReturn(...)} argument (which would trip Mockito's
     * nested-stubbing detector, since {@code MfaSession.isExpired()} is itself a
     * stubbed call).
     */
    private MfaSession liveSessionRegistered() {
        MfaSession session = mock(MfaSession.class);
        lenient().when(session.isExpired()).thenReturn(false);
        lenient().when(session.isCompleted()).thenReturn(false);
        lenient().when(session.getUserId()).thenReturn(SERVER_USER_ID);
        lenient().when(session.getTenantId()).thenReturn(SERVER_TENANT_ID);
        lenient().when(session.getFlowId()).thenReturn(FLOW_ID);
        lenient().when(session.getCurrentStep()).thenReturn(1);
        when(mfaSessionRepository.findBySessionToken(SESSION_TOKEN)).thenReturn(Optional.of(session));
        return session;
    }

    /** Stub a flow whose step-1 config carries a puzzleConfig allow-list. */
    private void stubPuzzleStepConfig() {
        AuthFlowStep step = mock(AuthFlowStep.class);
        lenient().when(step.getStepOrder()).thenReturn(1);
        lenient().when(step.getConfig()).thenReturn(
                "{\"puzzleConfig\":{\"count\":2,\"allowedChallengeTypes\":[\"blink\",\"smile\"],"
                        + "\"difficulty\":\"standard\"}}");
        AuthFlow flow = mock(AuthFlow.class);
        lenient().when(flow.getSteps()).thenReturn(List.of(step));
        lenient().when(authFlowRepository.findById(FLOW_ID)).thenReturn(Optional.of(flow));
    }

    @Test
    @DisplayName("CREATE stamps the SERVER user_id/tenant_id; a client-supplied user_id is IGNORED")
    void create_stampsServerIdentity_ignoresClientUserId() throws Exception {
        liveSessionRegistered();
        stubPuzzleStepConfig();
        when(biometricService.createPuzzleSession(any(), any(), any(), anyInt(), any()))
                .thenReturn(Map.of("session_id", BIO_SESSION_ID,
                        "challenges", List.of(Map.of("action", "blink"), Map.of("action", "smile"))));

        // The client tries to smuggle a foreign user_id + tenant_id into the body.
        UUID forgedUser = UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd");
        UUID forgedTenant = UUID.fromString("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee");
        String body = "{\"sessionToken\":\"" + SESSION_TOKEN + "\","
                + "\"user_id\":\"" + forgedUser + "\","
                + "\"tenant_id\":\"" + forgedTenant + "\","
                + "\"allowedChallengeTypes\":[\"turn_left\"]}";

        mockMvc.perform(post("/api/v1/auth/mfa/puzzle/session")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.session_id").value(BIO_SESSION_ID));

        // bio MUST be called with the SERVER identity, never the client's.
        ArgumentCaptor<UUID> tenantCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<UUID> userCaptor = ArgumentCaptor.forClass(UUID.class);
        verify(biometricService).createPuzzleSession(
                tenantCaptor.capture(), userCaptor.capture(), any(), anyInt(), any());
        assertThat(userCaptor.getValue()).isEqualTo(SERVER_USER_ID);
        assertThat(tenantCaptor.getValue()).isEqualTo(SERVER_TENANT_ID);
        assertThat(userCaptor.getValue()).isNotEqualTo(forgedUser);
        assertThat(tenantCaptor.getValue()).isNotEqualTo(forgedTenant);
    }

    @Test
    @DisplayName("CREATE forwards the allow-list resolved from the SERVER step config, not the client body")
    void create_usesServerStepConfig_notClientAllowList() throws Exception {
        liveSessionRegistered();
        stubPuzzleStepConfig();
        when(biometricService.createPuzzleSession(any(), any(), any(), anyInt(), any()))
                .thenReturn(Map.of("session_id", BIO_SESSION_ID, "challenges", List.of()));

        String body = "{\"sessionToken\":\"" + SESSION_TOKEN + "\",\"allowedChallengeTypes\":[\"hand_flip\"]}";
        mockMvc.perform(post("/api/v1/auth/mfa/puzzle/session")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> typesCaptor = ArgumentCaptor.forClass(List.class);
        verify(biometricService).createPuzzleSession(
                eq(SERVER_TENANT_ID), eq(SERVER_USER_ID), typesCaptor.capture(), anyInt(), any());
        assertThat(typesCaptor.getValue()).containsExactlyInAnyOrder("blink", "smile");
        assertThat(typesCaptor.getValue()).doesNotContain("hand_flip");
    }

    @Test
    @DisplayName("CREATE with an unknown/expired session token → 401, no bio call")
    void create_invalidSession_returns401() throws Exception {
        when(mfaSessionRepository.findBySessionToken(SESSION_TOKEN)).thenReturn(Optional.empty());

        String body = "{\"sessionToken\":\"" + SESSION_TOKEN + "\"}";
        mockMvc.perform(post("/api/v1/auth/mfa/puzzle/session")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());

        verify(biometricService, never()).createPuzzleSession(any(), any(), any(), anyInt(), any());
    }

    @Test
    @DisplayName("CREATE when PuzzleLayerPolicy is OFF for the tenant → 404, no bio call")
    void create_puzzleLayerOff_returns404() throws Exception {
        liveSessionRegistered();
        when(puzzleLayerPolicy.isEnabledFor(SERVER_TENANT_ID)).thenReturn(false);

        String body = "{\"sessionToken\":\"" + SESSION_TOKEN + "\"}";
        mockMvc.perform(post("/api/v1/auth/mfa/puzzle/session")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNotFound());

        verify(biometricService, never()).createPuzzleSession(any(), any(), any(), anyInt(), any());
    }

    @Test
    @DisplayName("CREATE with no resolvable puzzleConfig → 422, no bio call")
    void create_noStepConfig_returns422() throws Exception {
        liveSessionRegistered();
        when(authFlowRepository.findById(FLOW_ID)).thenReturn(Optional.empty());

        String body = "{\"sessionToken\":\"" + SESSION_TOKEN + "\"}";
        mockMvc.perform(post("/api/v1/auth/mfa/puzzle/session")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnprocessableEntity());

        verify(biometricService, never()).createPuzzleSession(any(), any(), any(), anyInt(), any());
    }

    @Test
    @DisplayName("CREATE with a missing sessionToken → 400, no bio call")
    void create_missingToken_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/auth/mfa/puzzle/session")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());

        verify(biometricService, never()).createPuzzleSession(any(), any(), any(), anyInt(), any());
    }

    @Test
    @DisplayName("SUBMIT proxies the body (minus sessionToken) to bio and returns the per-challenge verdict")
    void submit_proxiesBody_returnsVerdict() throws Exception {
        liveSessionRegistered();
        when(biometricService.submitPuzzleChallenge(eq(BIO_SESSION_ID), any()))
                .thenReturn(Map.of("verified", true, "action", "blink"));

        String body = "{\"sessionToken\":\"" + SESSION_TOKEN + "\",\"action\":\"blink\","
                + "\"metrics\":{\"ear\":0.18},\"start_timestamp_ms\":1000000,"
                + "\"end_timestamp_ms\":1002500,\"confidence\":0.92}";

        mockMvc.perform(post("/api/v1/auth/mfa/puzzle/session/" + BIO_SESSION_ID + "/challenge")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(true));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> bodyCaptor = ArgumentCaptor.forClass(Map.class);
        verify(biometricService).submitPuzzleChallenge(eq(BIO_SESSION_ID), bodyCaptor.capture());
        // The transport-only sessionToken is stripped before forwarding.
        assertThat(bodyCaptor.getValue()).doesNotContainKey("sessionToken");
        assertThat(bodyCaptor.getValue()).containsEntry("action", "blink");
        assertThat(bodyCaptor.getValue()).containsKey("metrics");
    }

    @Test
    @DisplayName("SUBMIT with an invalid session token → 401, no bio call")
    void submit_invalidSession_returns401() throws Exception {
        when(mfaSessionRepository.findBySessionToken(SESSION_TOKEN)).thenReturn(Optional.empty());

        String body = "{\"sessionToken\":\"" + SESSION_TOKEN + "\",\"action\":\"blink\"}";
        mockMvc.perform(post("/api/v1/auth/mfa/puzzle/session/" + BIO_SESSION_ID + "/challenge")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());

        verify(biometricService, never()).submitPuzzleChallenge(anyString(), any());
    }

    @Test
    @DisplayName("SUBMIT when bio returns a fail-closed error map (404) → upstream-failure status")
    void submit_bioFailClosed_returnsUpstreamFailure() throws Exception {
        liveSessionRegistered();
        when(biometricService.submitPuzzleChallenge(eq(BIO_SESSION_ID), any()))
                .thenReturn(Map.of("success", false, "message", "Puzzle challenge submit rejected: 404"));

        String body = "{\"sessionToken\":\"" + SESSION_TOKEN + "\",\"action\":\"blink\"}";
        mockMvc.perform(post("/api/v1/auth/mfa/puzzle/session/" + BIO_SESSION_ID + "/challenge")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadGateway());
    }
}
