package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Attempt;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Finish;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.NewAttempt;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Verdicts;
import com.fivucsas.identity.entity.AuthorTrialAttemptEntity;
import com.fivucsas.identity.entity.AuthorTrialParticipantEntity;
import com.fivucsas.identity.entity.AuthorTrialPlanEntryEntity;
import com.fivucsas.identity.repository.AuthorTrialAttemptRepository;
import com.fivucsas.identity.repository.AuthorTrialParticipantRepository;
import com.fivucsas.identity.repository.AuthorTrialPlanEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("AuthorTrialStoreAdapter — authoritative decision writes")
class AuthorTrialStoreAdapterTest {

    private static final UUID TENANT = UUID.fromString("aaaaaaaa-1111-2222-3333-444444444444");
    private static final UUID ATTEMPT_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID MFA_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final Instant NOW = Instant.parse("2026-11-24T20:00:00Z");

    private AuthorTrialAttemptRepository attemptRepository;
    private AuthorTrialParticipantRepository participantRepository;
    private AuthorTrialPlanEntryRepository planRepository;
    private AuthorTrialStoreAdapter adapter;
    private AuthorTrialAttemptEntity entity;

    @BeforeEach
    void setUp() {
        attemptRepository = mock(AuthorTrialAttemptRepository.class);
        participantRepository = mock(AuthorTrialParticipantRepository.class);
        planRepository = mock(AuthorTrialPlanEntryRepository.class);
        adapter = new AuthorTrialStoreAdapter(participantRepository, planRepository, attemptRepository);

        entity = new AuthorTrialAttemptEntity();
        entity.setId(ATTEMPT_ID);
        entity.setTenantId(TENANT);
        entity.setParticipantCode("P1");
        entity.setMode("genuine");
        entity.setTargetCode("P1");
        entity.setPlannedChallenge("blink");
        entity.setChallenge("blink");
        entity.setRoundNo(1);
        entity.setPosition(1);
        entity.setBinding(true);
        entity.setDifficulty("easy");
        entity.setChallengeCount(1);
        entity.setStartedAt(NOW);
        entity.setCreatedAt(NOW);
        entity.setUpdatedAt(NOW);
        when(attemptRepository.findById(ATTEMPT_ID)).thenReturn(Optional.of(entity));
        when(attemptRepository.findByMfaSessionId(MFA_ID)).thenReturn(Optional.of(entity));
    }

    @Test
    void recordVerdicts_FailureIsARejectWithTheReason() {
        adapter.recordVerdicts(MFA_ID, new Verdicts("fail", null, "fail", "liveness_verdict_failed",
                null, null, null, NOW.plusSeconds(5)));

        assertThat(entity.getLivenessVerdict()).isEqualTo("fail");
        assertThat(entity.getStepOutcome()).isEqualTo("fail");
        assertThat(entity.getOutcome()).isEqualTo("reject");
        assertThat(entity.getFailureReason()).isEqualTo("liveness_verdict_failed");
        assertThat(entity.getDecidedAt()).isEqualTo(NOW.plusSeconds(5));
    }

    @Test
    void recordVerdicts_PassRecordsScoresButLeavesTheDecisionOpen() {
        adapter.recordVerdicts(MFA_ID, new Verdicts("pass", "pass", "pass", null,
                0.71, 0.29, 0.40, NOW.plusSeconds(5)));

        assertThat(entity.getLivenessVerdict()).isEqualTo("pass");
        assertThat(entity.getIdentityVerdict()).isEqualTo("pass");
        assertThat(entity.getStepOutcome()).isEqualTo("pass");
        assertThat(entity.getOutcome()).isNull();
        assertThat(entity.getIdentityScore()).isEqualTo(0.71);
        assertThat(entity.getIdentityDistance()).isEqualTo(0.29);
        assertThat(entity.getIdentityThreshold()).isEqualTo(0.40);
    }

    @Test
    void recordAccept_IsTheOnlyPathToAnAccept() {
        entity.setOutcome("reject");
        entity.setFailureReason("identity_match_failed");

        adapter.recordAccept(MFA_ID, NOW.plusSeconds(9));

        assertThat(entity.getOutcome()).isEqualTo("accept");
        assertThat(entity.getStepOutcome()).isEqualTo("pass");
        assertThat(entity.getFailureReason()).isNull();
        assertThat(entity.getDecidedAt()).isEqualTo(NOW.plusSeconds(9));
    }

    @Test
    void finish_ClientAcceptedWithoutServerCompletion_BecomesReject() {
        adapter.recordFinish(ATTEMPT_ID, new Finish("accepted", null, 1200, null, null, NOW));

        assertThat(entity.getOutcome()).isEqualTo("reject");
        assertThat(entity.getFailureReason()).isEqualTo("server_did_not_authenticate");
        assertThat(entity.getClientLatencyMs()).isEqualTo(1200);
        assertThat(entity.getDecidedAt()).isEqualTo(NOW);
    }

    @Test
    void finish_TechnicalErrorIsExcludedButKeepsTheServerVerdict() {
        adapter.recordFinish(ATTEMPT_ID, new Finish("error", "camera_timeout", 900, null, null, NOW));

        assertThat(entity.getOutcome()).isEqualTo("error");
        assertThat(entity.getFailureReason()).isEqualTo("camera_timeout");
        assertThat(entity.getDecidedAt()).isEqualTo(NOW);
    }

    @Test
    void finish_ServerFailWinsOverAClientAccept() {
        entity.setLivenessVerdict("fail");
        entity.setStepOutcome("fail");

        adapter.recordFinish(ATTEMPT_ID, new Finish("accepted", null, 100, null, null, NOW));

        assertThat(entity.getOutcome()).isEqualTo("reject");
    }

    @Test
    void finish_NeverDowngradesAnAuthoritativeAcceptOrReject() {
        entity.setOutcome("accept");
        adapter.recordFinish(ATTEMPT_ID, new Finish("error", "camera_timeout", 10, null, null, NOW));
        assertThat(entity.getOutcome()).isEqualTo("accept");

        entity.setOutcome("reject");
        adapter.recordFinish(ATTEMPT_ID, new Finish("accepted", null, 10, null, null, NOW));
        assertThat(entity.getOutcome()).isEqualTo("reject");
    }

    @Test
    void finish_NoClientOutcomeAndNoServerVerdict_StaysPending() {
        adapter.recordFinish(ATTEMPT_ID, new Finish(null, null, 10, null, null, NOW));
        assertThat(entity.getOutcome()).isNull();
    }

    @Test
    void createAttempt_MapsEveryFieldAndReturnsTheId() {
        when(attemptRepository.saveAndFlush(any())).thenAnswer(inv -> {
            AuthorTrialAttemptEntity saved = inv.getArgument(0);
            saved.setId(ATTEMPT_ID);
            return saved;
        });

        UUID id = adapter.createAttempt(new NewAttempt(TENANT, "P1", "attack", "P2",
                "DeepFaceLive 2.0", "deepfake_replay", "blink", "smile", 2, 3, UUID.randomUUID(),
                true, "easy", 1, "audit", MFA_ID, NOW, "{\"label\":\"laptop\"}", "{\"brightness\":0.5}",
                "web-sha", "api-sha", "bio-sha"));

        assertThat(id).isEqualTo(ATTEMPT_ID);
        ArgumentCaptor<AuthorTrialAttemptEntity> captor = ArgumentCaptor.forClass(AuthorTrialAttemptEntity.class);
        verify(attemptRepository).saveAndFlush(captor.capture());
        AuthorTrialAttemptEntity saved = captor.getValue();
        assertThat(saved.getMode()).isEqualTo("attack");
        assertThat(saved.getTargetCode()).isEqualTo("P2");
        assertThat(saved.getInstrumentPreset()).isEqualTo("deepfake_replay");
        assertThat(saved.getChallenge()).isEqualTo("smile");
        assertThat(saved.getPlannedChallenge()).isEqualTo("blink");
        assertThat(saved.getDeviceJson()).contains("laptop");
        assertThat(saved.getChallengesSubmitted()).isZero();
    }

    @Test
    void attemptByMfaSessionId_MapsTheRow() {
        entity.setPuzzleSessionId("puzzle-1");
        entity.setTraceContract("v2");

        Attempt attempt = adapter.attemptByMfaSessionId(MFA_ID).orElseThrow();

        assertThat(attempt.id()).isEqualTo(ATTEMPT_ID);
        assertThat(attempt.participantCode()).isEqualTo("P1");
        assertThat(attempt.puzzleSessionId()).isEqualTo("puzzle-1");
        assertThat(attempt.traceContract()).isEqualTo("v2");
    }

    @Test
    void recordChallengeSubmit_IncrementsTheCounterAndStoreTheVerdict() {
        entity.setPuzzleSessionId("puzzle-1");
        when(attemptRepository.findByPuzzleSessionId("puzzle-1")).thenReturn(Optional.of(entity));

        adapter.recordChallengeSubmit("puzzle-1", "pass", null);

        assertThat(entity.getChallengesSubmitted()).isEqualTo(1);
        assertThat(entity.getLastChallengeVerdict()).isEqualTo("pass");
    }

    @Test
    void deleteForTenant_DeletesAttemptsPlansAndParticipants() {
        when(attemptRepository.findByTenantIdOrderByStartedAtAsc(any(), any())).thenReturn(List.of(entity));
        AuthorTrialParticipantEntity participant = new AuthorTrialParticipantEntity();
        participant.setId(UUID.randomUUID());
        participant.setTenantId(TENANT);
        participant.setParticipantCode("P1");
        participant.setUserId(UUID.randomUUID());
        when(participantRepository.findByTenantIdOrderByParticipantCodeAsc(TENANT))
                .thenReturn(List.of(participant));
        when(planRepository.deleteByTenantId(TENANT)).thenReturn(2L);

        com.fivucsas.identity.application.port.output.AuthorTrialStorePort.DeletionCounts counts =
                adapter.deleteForTenant(TENANT);

        assertThat(counts.attempts()).isEqualTo(1);
        assertThat(counts.planEntries()).isEqualTo(2);
        assertThat(counts.participants()).isEqualTo(1);
        verify(attemptRepository).deleteByTenantId(TENANT);
        verify(planRepository).deleteByTenantId(TENANT);
        verify(participantRepository).deleteByTenantId(TENANT);
    }
}