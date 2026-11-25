package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuthorTrialStorePort;
import com.fivucsas.identity.entity.AuthorTrialAttemptEntity;
import com.fivucsas.identity.entity.AuthorTrialParticipantEntity;
import com.fivucsas.identity.entity.AuthorTrialPlanEntryEntity;
import com.fivucsas.identity.repository.AuthorTrialAttemptRepository;
import com.fivucsas.identity.repository.AuthorTrialParticipantRepository;
import com.fivucsas.identity.repository.AuthorTrialPlanEntryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * JPA adapter for {@link AuthorTrialStorePort}. All reads/writes of the three
 * V90 tables live here so the application layer never sees a JPA entity.
 */
@Repository
@RequiredArgsConstructor
public class AuthorTrialStoreAdapter implements AuthorTrialStorePort {

    private final AuthorTrialParticipantRepository participantRepository;
    private final AuthorTrialPlanEntryRepository planEntryRepository;
    private final AuthorTrialAttemptRepository attemptRepository;

    @Override
    public List<Participant> participants(UUID tenantId) {
        return participantRepository.findByTenantIdOrderByParticipantCodeAsc(tenantId).stream()
                .map(AuthorTrialStoreAdapter::toParticipant)
                .toList();
    }

    @Override
    public Optional<Participant> participant(UUID tenantId, String participantCode) {
        if (tenantId == null || participantCode == null) {
            return Optional.empty();
        }
        return participantRepository.findByTenantIdAndParticipantCode(tenantId, participantCode)
                .map(AuthorTrialStoreAdapter::toParticipant);
    }

    @Override
    public void markEnrolled(UUID participantId, Instant at) {
        participantRepository.findById(participantId).ifPresent(p -> {
            p.setEnrolledAt(at);
            participantRepository.save(p);
        });
    }

    @Override
    public Optional<PlanSlot> lockNextFreeSlot(UUID tenantId, String participantCode, String mode) {
        return planEntryRepository.lockNextFreeSlot(tenantId, participantCode, mode)
                .map(e -> new PlanSlot(e.getId(), e.getRoundNo(), e.getPosition(), e.getChallenge()));
    }

    @Override
    public int maxRound(UUID tenantId, String participantCode, String mode) {
        return planEntryRepository.maxRound(tenantId, participantCode, mode);
    }

    @Override
    public void createRound(UUID tenantId, String participantCode, String mode, int roundNo, List<String> challenges) {
        Instant now = Instant.now();
        int position = 0;
        List<AuthorTrialPlanEntryEntity> rows = challenges.stream()
                .map(challenge -> {
                    AuthorTrialPlanEntryEntity e = new AuthorTrialPlanEntryEntity();
                    e.setTenantId(tenantId);
                    e.setParticipantCode(participantCode);
                    e.setMode(mode);
                    e.setRoundNo(roundNo);
                    e.setChallenge(challenge);
                    e.setCreatedAt(now);
                    return e;
                })
                .toList();
        for (AuthorTrialPlanEntryEntity row : rows) {
            // Position is assigned in the (already shuffled) list order.
            row.setPosition(++position);
        }
        // Flush so the immediately following lockNextFreeSlot() native query sees the
        // new round in this same transaction.
        planEntryRepository.saveAllAndFlush(rows);
    }

    @Override
    public void assignSlot(UUID slotId, UUID attemptId) {
        planEntryRepository.findById(slotId).ifPresent(e -> {
            e.setAttemptId(attemptId);
            planEntryRepository.save(e);
        });
    }

    @Override
    public UUID createAttempt(NewAttempt attempt) {
        Instant now = Instant.now();
        AuthorTrialAttemptEntity e = new AuthorTrialAttemptEntity();
        e.setTenantId(attempt.tenantId());
        e.setParticipantCode(attempt.participantCode());
        e.setMode(attempt.mode());
        e.setTargetCode(attempt.targetCode());
        e.setInstrument(attempt.instrument());
        e.setInstrumentPreset(attempt.instrumentPreset());
        e.setPlannedChallenge(attempt.plannedChallenge());
        e.setChallenge(attempt.challenge());
        e.setRoundNo(attempt.roundNo());
        e.setPosition(attempt.position());
        e.setPlanEntryId(attempt.planEntryId());
        e.setBinding(attempt.binding());
        e.setDifficulty(attempt.difficulty());
        e.setChallengeCount(attempt.challengeCount());
        e.setLivenessMode(attempt.livenessMode());
        e.setMfaSessionId(attempt.mfaSessionId());
        e.setStartedAt(attempt.startedAt());
        e.setDeviceJson(attempt.deviceJson());
        e.setEnvJson(attempt.envJson());
        e.setWebVersion(attempt.webVersion());
        e.setApiVersion(attempt.apiVersion());
        e.setBioVersion(attempt.bioVersion());
        e.setChallengesSubmitted(0);
        e.setCreatedAt(now);
        e.setUpdatedAt(now);
        AuthorTrialAttemptEntity saved = attemptRepository.saveAndFlush(e);
        return saved.getId();
    }

    @Override
    public Optional<Attempt> attempt(UUID attemptId) {
        return attemptRepository.findById(attemptId).map(AuthorTrialStoreAdapter::toAttempt);
    }

    @Override
    public Optional<Attempt> attemptByMfaSessionId(UUID mfaSessionId) {
        if (mfaSessionId == null) {
            return Optional.empty();
        }
        return attemptRepository.findByMfaSessionId(mfaSessionId).map(AuthorTrialStoreAdapter::toAttempt);
    }

    @Override
    public Optional<Attempt> attemptByPuzzleSessionId(String puzzleSessionId) {
        if (puzzleSessionId == null || puzzleSessionId.isBlank()) {
            return Optional.empty();
        }
        return attemptRepository.findByPuzzleSessionId(puzzleSessionId).map(AuthorTrialStoreAdapter::toAttempt);
    }

    @Override
    public void recordPuzzleSession(UUID attemptId, String puzzleSessionId, String traceContract, String issuedChallenge) {
        attemptRepository.findById(attemptId).ifPresent(e -> {
            e.setPuzzleSessionId(puzzleSessionId);
            e.setTraceContract(traceContract);
            if (issuedChallenge != null && !issuedChallenge.isBlank()) {
                e.setChallenge(issuedChallenge);
            }
            e.setUpdatedAt(Instant.now());
            attemptRepository.save(e);
        });
    }

    @Override
    public void recordChallengeSubmit(String puzzleSessionId, String verdict, String reason) {
        attemptRepository.findByPuzzleSessionId(puzzleSessionId).ifPresent(e -> {
            e.setChallengesSubmitted(e.getChallengesSubmitted() + 1);
            e.setLastChallengeVerdict(verdict);
            e.setLastChallengeReason(truncate(reason, 80));
            e.setUpdatedAt(Instant.now());
            attemptRepository.save(e);
        });
    }

    @Override
    public void recordVerdicts(UUID mfaSessionId, Verdicts verdicts) {
        attemptRepository.findByMfaSessionId(mfaSessionId).ifPresent(e -> {
            e.setLivenessVerdict(verdicts.livenessVerdict());
            e.setIdentityVerdict(verdicts.identityVerdict());
            e.setStepOutcome(verdicts.stepOutcome());
            if (verdicts.failureReason() != null) {
                e.setFailureReason(truncate(verdicts.failureReason(), 200));
            }
            if (verdicts.identityScore() != null) {
                e.setIdentityScore(verdicts.identityScore());
            }
            if (verdicts.identityDistance() != null) {
                e.setIdentityDistance(verdicts.identityDistance());
            }
            if (verdicts.identityThreshold() != null) {
                e.setIdentityThreshold(verdicts.identityThreshold());
            }
            if ("fail".equals(verdicts.stepOutcome())) {
                e.setOutcome("reject");
                e.setDecidedAt(verdicts.at());
            }
            e.setUpdatedAt(verdicts.at());
            attemptRepository.save(e);
        });
    }

    @Override
    public void recordAccept(UUID mfaSessionId, Instant at) {
        attemptRepository.findByMfaSessionId(mfaSessionId).ifPresent(e -> {
            e.setOutcome("accept");
            e.setStepOutcome("pass");
            e.setFailureReason(null);
            e.setDecidedAt(at);
            e.setUpdatedAt(at);
            attemptRepository.save(e);
        });
    }

    @Override
    public void recordFinish(UUID attemptId, Finish finish) {
        attemptRepository.findById(attemptId).ifPresent(e -> {
            if (finish.clientLatencyMs() != null) {
                e.setClientLatencyMs(finish.clientLatencyMs());
            }
            if (e.getDeviceJson() == null && finish.deviceJson() != null) {
                e.setDeviceJson(finish.deviceJson());
            }
            if (e.getEnvJson() == null && finish.envJson() != null) {
                e.setEnvJson(finish.envJson());
            }
            e.setUpdatedAt(finish.at());

            // Authoritative outcomes are never downgraded or upgraded by the page.
            boolean authoritative = "accept".equals(e.getOutcome()) || "reject".equals(e.getOutcome());
            if (!authoritative) {
                boolean serverFail = "fail".equals(e.getStepOutcome())
                        || "fail".equals(e.getLivenessVerdict())
                        || "fail".equals(e.getIdentityVerdict());
                String client = finish.clientOutcome() == null ? "" : finish.clientOutcome();
                if (serverFail) {
                    e.setOutcome("reject");
                } else if ("error".equals(client) || "abandoned".equals(client)) {
                    e.setOutcome(client);
                } else if ("rejected".equals(client)) {
                    e.setOutcome("reject");
                } else if ("accepted".equals(client)) {
                    // The page cannot mint an accept: only the real MFA completion can.
                    e.setOutcome("reject");
                    if (e.getFailureReason() == null) {
                        e.setFailureReason("server_did_not_authenticate");
                    }
                } else {
                    // No client outcome and no server verdict yet: stay pending.
                    attemptRepository.save(e);
                    return;
                }
                if (e.getDecidedAt() == null) {
                    e.setDecidedAt(finish.at());
                }
                if (e.getFailureReason() == null && finish.failureReason() != null
                        && !finish.failureReason().isBlank()) {
                    e.setFailureReason(truncate(finish.failureReason(), 200));
                }
            }
            attemptRepository.save(e);
        });
    }

    @Override
    public List<Attempt> attemptsForExport(UUID tenantId, int limit) {
        return attemptRepository.findByTenantIdOrderByStartedAtAsc(tenantId, PageRequest.of(0, limit)).stream()
                .map(AuthorTrialStoreAdapter::toAttempt)
                .toList();
    }

    @Override
    @Transactional
    public DeletionCounts deleteForTenant(UUID tenantId) {
        List<AuthorTrialAttemptEntity> attempts = attemptRepository
                .findByTenantIdOrderByStartedAtAsc(tenantId, PageRequest.of(0, Integer.MAX_VALUE));
        List<AuthorTrialParticipantEntity> participants =
                participantRepository.findByTenantIdOrderByParticipantCodeAsc(tenantId);
        int attemptsDeleted = attempts.size();
        int participantsDeleted = participants.size();
        int plansDeleted = (int) planEntryRepository.deleteByTenantId(tenantId);
        attemptRepository.deleteByTenantId(tenantId);
        participantRepository.deleteByTenantId(tenantId);
        return new DeletionCounts(attemptsDeleted, plansDeleted, participantsDeleted);
    }

    private static Participant toParticipant(AuthorTrialParticipantEntity e) {
        return new Participant(e.getId(), e.getTenantId(), e.getParticipantCode(), e.getUserId(), e.getEnrolledAt());
    }

    private static Attempt toAttempt(AuthorTrialAttemptEntity e) {
        return new Attempt(
                e.getId(), e.getTenantId(), e.getParticipantCode(), e.getMode(), e.getTargetCode(),
                e.getInstrument(), e.getInstrumentPreset(), e.getPlannedChallenge(), e.getChallenge(),
                e.getRoundNo(), e.getPosition(), e.getPlanEntryId(), e.isBinding(), e.getDifficulty(),
                e.getChallengeCount(), e.getLivenessMode(), e.getTraceContract(), e.getMfaSessionId(),
                e.getPuzzleSessionId(), e.getStartedAt(), e.getDecidedAt(), e.getOutcome(),
                e.getLivenessVerdict(), e.getIdentityVerdict(), e.getStepOutcome(), e.getFailureReason(),
                e.getIdentityScore(), e.getIdentityDistance(), e.getIdentityThreshold(),
                e.getClientLatencyMs(), e.getChallengesSubmitted(), e.getLastChallengeVerdict(),
                e.getLastChallengeReason(), e.getDeviceJson(), e.getEnvJson(), e.getWebVersion(),
                e.getApiVersion(), e.getBioVersion());
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.length() <= max ? trimmed : trimmed.substring(0, max);
    }
}