package com.fivucsas.identity.application.service.authorTrial;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.port.input.AuthenticateUserUseCase;
import com.fivucsas.identity.application.port.input.AuthorTrialUseCase;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.NewAttempt;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Participant;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.PlanSlot;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.FaceEmbeddingLivenessPolicy;
import com.fivucsas.identity.application.service.LoginAccountStateGuard;
import com.fivucsas.identity.application.service.PuzzleLayerPolicy;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.user.User;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.repository.MfaSessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthorTrialService — plan, real MFA session, enrollment, export")
class AuthorTrialServiceTest {

    private static final UUID TENANT = UUID.fromString("aaaaaaaa-1111-2222-3333-444444444444");
    private static final UUID P1_USER = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID P2_USER = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID P1_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
    private static final UUID P2_ID = UUID.fromString("44444444-4444-4444-4444-444444444444");
    private static final UUID SLOT_ID = UUID.fromString("55555555-5555-5555-5555-555555555555");
    private static final UUID ATTEMPT_ID = UUID.fromString("66666666-6666-6666-6666-666666666666");
    private static final UUID MFA_ID = UUID.fromString("77777777-7777-7777-7777-777777777777");
    private static final String CONFIG = """
            {"puzzleConfig":{"allowedChallengeTypes":["blink","smile"],
             "count":1,"difficulty":"easy","alsoMatchFaceIdentity":true}}
            """;

    @Mock private AuthorTrialStorePort store;
    @Mock private UserDomainRepository userDomainRepository;
    @Mock private AuthenticateUserUseCase authenticateUserUseCase;
    @Mock private LoginAccountStateGuard loginAccountStateGuard;
    @Mock private ManageEnrollmentUseCase manageEnrollmentUseCase;
    @Mock private BiometricServicePort biometricService;
    @Mock private AuthFlowRepositoryPort authFlowRepository;
    @Mock private PuzzleLayerPolicy puzzleLayerPolicy;
    @Mock private ClientSideEmbeddingPolicy clientSideEmbeddingPolicy;
    @Mock private FaceEmbeddingLivenessPolicy faceEmbeddingLivenessPolicy;
    @Mock private MfaSessionRepository mfaSessionRepository;

    private AuthorTrialProperties properties;
    private AuthorTrialService service;
    private Participant p1;
    private Participant p2;
    private AuthFlow flow;
    private AuthFlowStep step;
    private AuthMethod method;

    @BeforeEach
    void setUp() {
        properties = new AuthorTrialProperties();
        properties.setEnabled(true);
        properties.setAccessCode("shared-secret");
        properties.setTenantIds(List.of(TENANT.toString()));
        properties.setApiVersion("api-sha");
        properties.setFallbackBioVersion("bio-sha");
        AuthorTrialAccessGuard guard = new AuthorTrialAccessGuard(properties);
        service = new AuthorTrialService(store, properties, guard, userDomainRepository,
                authenticateUserUseCase, loginAccountStateGuard, manageEnrollmentUseCase,
                biometricService, authFlowRepository, puzzleLayerPolicy,
                clientSideEmbeddingPolicy, faceEmbeddingLivenessPolicy, mfaSessionRepository,
                new ObjectMapper().findAndRegisterModules());

        p1 = new Participant(P1_ID, TENANT, "P1", P1_USER, Instant.parse("2026-11-20T10:00:00Z"));
        p2 = new Participant(P2_ID, TENANT, "P2", P2_USER, null);
        lenient().when(store.participant(TENANT, "P1")).thenReturn(Optional.of(p1));
        lenient().when(store.participant(TENANT, "P2")).thenReturn(Optional.of(p2));
        lenient().when(puzzleLayerPolicy.isEnabledFor(TENANT)).thenReturn(true);
        lenient().when(clientSideEmbeddingPolicy.isEnabledForTenant(TENANT)).thenReturn(true);
        lenient().when(faceEmbeddingLivenessPolicy.modeFor(TENANT))
                .thenReturn(FaceEmbeddingLivenessPolicy.Mode.AUDIT);

        flow = mock(AuthFlow.class);
        step = mock(AuthFlowStep.class);
        method = mock(AuthMethod.class);
        lenient().when(authFlowRepository
                .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(TENANT, OperationType.APP_LOGIN))
                .thenReturn(Optional.of(flow));
        lenient().when(flow.getSteps()).thenReturn(List.of(step));
        lenient().when(step.getStepOrder()).thenReturn(1);
        lenient().when(step.getAvailableMethods()).thenReturn(List.of(method));
        lenient().when(method.getType()).thenReturn(AuthMethodType.PUZZLE);
        lenient().when(step.getConfig()).thenReturn(CONFIG);
    }

    private User user(UUID id, String email) {
        User user = mock(User.class);
        lenient().when(user.getTenantId()).thenReturn(TENANT);
        lenient().when(user.getEmail()).thenReturn(email);
        return user;
    }

    private void stubHappySession() {
        when(store.lockNextFreeSlot(eq(TENANT), eq("P1"), eq("genuine")))
                .thenReturn(Optional.of(new PlanSlot(SLOT_ID, 1, 1, "blink")));
        User target = user(P1_USER, "p1@trial.test");
        when(userDomainRepository.findById(P1_USER)).thenReturn(Optional.of(target));
        when(authenticateUserUseCase.beginIdentifierLogin(anyString(), isNull(), anyString(), any()))
                .thenReturn(AuthenticationResponse.ofMfaPending("token-1", 1, 1, "PUZZLE",
                        List.of(), null, List.of()));
        MfaSession mfa = mock(MfaSession.class);
        when(mfa.getId()).thenReturn(MFA_ID);
        when(mfaSessionRepository.findBySessionToken("token-1")).thenReturn(Optional.of(mfa));
        when(store.createAttempt(any())).thenReturn(ATTEMPT_ID);
    }

    @Test
    void participants_ReturnsCodesAndFlowWithoutPii() {
        when(store.participants(TENANT)).thenReturn(List.of(p1, p2));

        AuthorTrialUseCase.ParticipantsView view = service.participants();

        assertThat(view.tenantId()).isEqualTo(TENANT);
        assertThat(view.participants()).extracting(AuthorTrialUseCase.ParticipantView::code)
                .containsExactly("P1", "P2");
        assertThat(view.participants().get(0).enrolled()).isTrue();
        assertThat(view.participants().get(1).enrolled()).isFalse();
        assertThat(view.flow().method()).isEqualTo("PUZZLE");
        assertThat(view.flow().binding()).isTrue();
        assertThat(view.flow().challenges()).containsExactly("blink", "smile");
    }

    @Test
    void startSession_Genuine_UsesPlanSlotAndRealMfaSession() {
        stubHappySession();

        AuthorTrialUseCase.SessionView view = service.startSession(
                new AuthorTrialUseCase.StartRequest("P1", "genuine", null, null, null,
                        null, null, "web-sha"), "1.2.3.4", "JUnit");

        assertThat(view.attemptId()).isEqualTo(ATTEMPT_ID);
        assertThat(view.mfaSessionToken()).isEqualTo("token-1");
        assertThat(view.participantCode()).isEqualTo("P1");
        assertThat(view.targetCode()).isEqualTo("P1");
        assertThat(view.mode()).isEqualTo("genuine");
        assertThat(view.round()).isEqualTo(1);
        assertThat(view.position()).isEqualTo(1);
        assertThat(view.challenge()).isEqualTo("blink");
        assertThat(view.binding()).isTrue();
        assertThat(view.puzzleConfig().allowedChallengeTypes()).containsExactly("blink");
        assertThat(view.puzzleConfig().count()).isEqualTo(1);

        verify(loginAccountStateGuard).clearLock(P1_USER);
        verify(store).assignSlot(SLOT_ID, ATTEMPT_ID);
        ArgumentCaptor<NewAttempt> captor = ArgumentCaptor.forClass(NewAttempt.class);
        verify(store).createAttempt(captor.capture());
        NewAttempt attempt = captor.getValue();
        assertThat(attempt.mode()).isEqualTo("genuine");
        assertThat(attempt.targetCode()).isEqualTo("P1");
        assertThat(attempt.binding()).isTrue();
        assertThat(attempt.difficulty()).isEqualTo("easy");
        assertThat(attempt.challengeCount()).isEqualTo(1);
        assertThat(attempt.livenessMode()).isEqualTo("audit");
        assertThat(attempt.apiVersion()).isEqualTo("api-sha");
        assertThat(attempt.webVersion()).isEqualTo("web-sha");
        assertThat(attempt.mfaSessionId()).isEqualTo(MFA_ID);
    }

    @Test
    void startSession_Attack_RequiresAnotherTargetAndInstrument() {
        assertThatThrownBy(() -> service.startSession(
                new AuthorTrialUseCase.StartRequest("P1", "attack", "P1", "tool", "other",
                        null, null, null), "ip", "ua"))
                .isInstanceOf(AuthorTrialException.class)
                .extracting(e -> ((AuthorTrialException) e).code())
                .isEqualTo("TRIAL_TARGET_MUST_DIFFER");

        assertThatThrownBy(() -> service.startSession(
                new AuthorTrialUseCase.StartRequest("P1", "attack", "P2", "  ", null,
                        null, null, null), "ip", "ua"))
                .isInstanceOf(AuthorTrialException.class)
                .extracting(e -> ((AuthorTrialException) e).code())
                .isEqualTo("TRIAL_INSTRUMENT_REQUIRED");

        assertThatThrownBy(() -> service.startSession(
                new AuthorTrialUseCase.StartRequest("P9", "genuine", null, null, null,
                        null, null, null), "ip", "ua"))
                .isInstanceOf(AuthorTrialException.class)
                .extracting(e -> ((AuthorTrialException) e).code())
                .isEqualTo("TRIAL_PARTICIPANT_UNKNOWN");
    }

    @Test
    void startSession_Attack_CreatesAttemptAgainstTheTargetAccount() {
        when(store.lockNextFreeSlot(eq(TENANT), eq("P1"), eq("attack")))
                .thenReturn(Optional.of(new PlanSlot(SLOT_ID, 2, 1, "smile")));
        User target = user(P2_USER, "p2@trial.test");
        when(userDomainRepository.findById(P2_USER)).thenReturn(Optional.of(target));
        when(authenticateUserUseCase.beginIdentifierLogin(anyString(), isNull(), anyString(), any()))
                .thenReturn(AuthenticationResponse.ofMfaPending("token-2", 1, 1, "PUZZLE",
                        List.of(), null, List.of()));
        MfaSession mfa = mock(MfaSession.class);
        when(mfa.getId()).thenReturn(MFA_ID);
        when(mfaSessionRepository.findBySessionToken("token-2")).thenReturn(Optional.of(mfa));
        when(store.createAttempt(any())).thenReturn(ATTEMPT_ID);

        AuthorTrialUseCase.SessionView view = service.startSession(
                new AuthorTrialUseCase.StartRequest("P1", "attack", "P2", "DeepFaceLive 2.0",
                        "deepfake_replay", null, null, null), "ip", "ua");

        assertThat(view.mode()).isEqualTo("attack");
        assertThat(view.targetCode()).isEqualTo("P2");
        assertThat(view.position()).isEqualTo(1);
        verify(loginAccountStateGuard).clearLock(P2_USER);
        ArgumentCaptor<NewAttempt> captor = ArgumentCaptor.forClass(NewAttempt.class);
        verify(store).createAttempt(captor.capture());
        assertThat(captor.getValue().instrument()).isEqualTo("DeepFaceLive 2.0");
        assertThat(captor.getValue().instrumentPreset()).isEqualTo("deepfake_replay");
    }

    @Test
    void startSession_WhenRoundExhausted_CreatesAShuffledFullRound() {
        when(store.lockNextFreeSlot(eq(TENANT), eq("P1"), eq("genuine")))
                .thenReturn(Optional.empty(),
                        Optional.of(new PlanSlot(SLOT_ID, 3, 1, "blink")));
        when(store.maxRound(TENANT, "P1", "genuine")).thenReturn(2);
        User target = user(P1_USER, "p1@trial.test");
        when(userDomainRepository.findById(P1_USER)).thenReturn(Optional.of(target));
        when(authenticateUserUseCase.beginIdentifierLogin(anyString(), isNull(), anyString(), any()))
                .thenReturn(AuthenticationResponse.ofMfaPending("token-3", 1, 1, "PUZZLE",
                        List.of(), null, List.of()));
        MfaSession mfa = mock(MfaSession.class);
        when(mfa.getId()).thenReturn(MFA_ID);
        when(mfaSessionRepository.findBySessionToken("token-3")).thenReturn(Optional.of(mfa));
        when(store.createAttempt(any())).thenReturn(ATTEMPT_ID);

        service.startSession(new AuthorTrialUseCase.StartRequest("P1", "genuine", null, null,
                null, null, null, null), "ip", "ua");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> round = ArgumentCaptor.forClass(List.class);
        verify(store).createRound(eq(TENANT), eq("P1"), eq("genuine"), eq(3), round.capture());
        assertThat(round.getValue()).containsExactlyInAnyOrder("blink", "smile");
    }

    @Test
    void startSession_FailsClosedWhenFlowIsNotPuzzleFirst() {
        when(step.getAvailableMethods()).thenReturn(List.of());

        assertThatThrownBy(() -> service.startSession(
                new AuthorTrialUseCase.StartRequest("P1", "genuine", null, null, null,
                        null, null, null), "ip", "ua"))
                .isInstanceOf(AuthorTrialException.class)
                .extracting(e -> ((AuthorTrialException) e).code())
                .isEqualTo("TRIAL_FLOW_NOT_PUZZLE_FIRST");
        verify(store, never()).createAttempt(any());
    }

    @Test
    void finish_UsesTheAuthoritativeOutcomeFromTheStore() {
        AuthorTrialStorePort.Attempt pending = attempt("P1", "genuine", null, null);
        when(store.attempt(ATTEMPT_ID)).thenReturn(Optional.of(pending),
                Optional.of(attempt("P1", "genuine", "accept", null)));

        AuthorTrialUseCase.FinishView view = service.finish(ATTEMPT_ID,
                new AuthorTrialUseCase.FinishRequest("error", 1234, "camera_timeout", null, null));

        assertThat(view.outcome()).isEqualTo("accept");
        assertThat(view.excluded()).isFalse();
        verify(store).recordFinish(eq(ATTEMPT_ID), any());
    }

    @Test
    void enroll_Requires512FiniteFloats() {
        assertThatThrownBy(() -> service.enroll(new AuthorTrialUseCase.EnrollRequest(
                "P1", List.of(0.1, 0.2), null)))
                .isInstanceOf(AuthorTrialException.class)
                .extracting(e -> ((AuthorTrialException) e).code())
                .isEqualTo("TRIAL_EMBEDDING_512_REQUIRED");

        List<Double> bad = new java.util.ArrayList<>(java.util.Collections.nCopies(512, 0.1));
        bad.set(3, Double.NaN);
        assertThatThrownBy(() -> service.enroll(new AuthorTrialUseCase.EnrollRequest("P1", bad, null)))
                .isInstanceOf(AuthorTrialException.class)
                .extracting(e -> ((AuthorTrialException) e).code())
                .isEqualTo("TRIAL_EMBEDDING_INVALID");
    }

    @Test
    void enroll_SuccessCompletesBothEnrollments() {
        User target = user(P1_USER, "p1@trial.test");
        when(userDomainRepository.findById(P1_USER)).thenReturn(Optional.of(target));
        when(biometricService.enrollEmbedding(eq(TENANT.toString()), eq(P1_USER), any()))
                .thenReturn(Map.of("success", true));

        AuthorTrialUseCase.EnrollView view = service.enroll(new AuthorTrialUseCase.EnrollRequest(
                "P1", java.util.Collections.nCopies(512, 0.1), "web-sha"));

        assertThat(view.enrolled()).isTrue();
        verify(manageEnrollmentUseCase).completeEnrollment(P1_USER, AuthMethodType.FACE, "{}");
        verify(manageEnrollmentUseCase).completeEnrollment(P1_USER, AuthMethodType.PUZZLE, "{}");
        verify(store).markEnrolled(eq(P1_ID), any());
    }

    @Test
    void enroll_MapsFaceImageRequiredToAConflict() {
        User target = user(P1_USER, "p1@trial.test");
        when(userDomainRepository.findById(P1_USER)).thenReturn(Optional.of(target));
        when(biometricService.enrollEmbedding(eq(TENANT.toString()), eq(P1_USER), any()))
                .thenReturn(Map.of("success", false, "message", "Enrollment rejected: FACE_IMAGE_REQUIRED"));

        assertThatThrownBy(() -> service.enroll(new AuthorTrialUseCase.EnrollRequest(
                "P1", java.util.Collections.nCopies(512, 0.1), null)))
                .isInstanceOf(AuthorTrialException.class)
                .extracting(e -> ((AuthorTrialException) e).code())
                .isEqualTo("TRIAL_ENROLL_IMAGE_REQUIRED");
        verify(manageEnrollmentUseCase, never()).completeEnrollment(any(), any(), anyString());
    }

    @Test
    void export_CsvNumbersSessionsPerTargetAndKeepsTheSchema() {
        when(store.attemptsForExport(TENANT, properties.getExportLimit())).thenReturn(List.of(
                attempt("P1", "genuine", "accept", null),
                attempt("P2", "genuine", "reject", null),
                attempt("P1", "genuine", "reject", null)));

        AuthorTrialUseCase.ExportView view = service.export("csv");

        String[] lines = view.body().split("\n");
        assertThat(lines).hasSize(4);
        assertThat(lines[0]).startsWith("date,participant,operator");
        assertThat(lines[1]).contains(",P1,P1,1,");
        assertThat(lines[2]).contains(",P2,P2,1,");
        assertThat(lines[3]).contains(",P1,P1,2,");
        assertThat(view.contentType()).startsWith("text/csv");
        assertThat(view.filename()).isEqualTo("author_trial_sessions.csv");
    }

    @Test
    void export_JsonIsAnArray() {
        when(store.attemptsForExport(TENANT, properties.getExportLimit()))
                .thenReturn(List.of(attempt("P1", "genuine", "accept", null)));

        AuthorTrialUseCase.ExportView view = service.export("json");

        assertThat(view.body()).contains("\"participantCode\" : \"P1\"");
        assertThat(view.contentType()).isEqualTo("application/json");
    }

    @Test
    void disabledSurface_AnswersNotFound() {
        properties.setEnabled(false);
        assertThatThrownBy(service::participants)
                .isInstanceOf(AuthorTrialException.class)
                .extracting(e -> ((AuthorTrialException) e).code())
                .isEqualTo("AUTHOR_TRIAL_DISABLED");
    }

    private static AuthorTrialStorePort.Attempt attempt(String code, String mode,
                                                        String outcome, String failure) {
        Instant start = Instant.parse("2026-11-24T18:00:00Z");
        return new AuthorTrialStorePort.Attempt(ATTEMPT_ID, TENANT, code, mode, code,
                null, null, "blink", "blink", 1, 1, null, true, "easy", 1, "audit",
                "v2", MFA_ID, "puzzle-1", start, start.plusSeconds(10), outcome,
                "pass", "pass", "pass".equals(outcome) ? "pass" : "fail", failure,
                0.7, 0.3, 0.4, 500, 1, "pass", null, "{}", "{}", "web", "api", "bio");
    }
}