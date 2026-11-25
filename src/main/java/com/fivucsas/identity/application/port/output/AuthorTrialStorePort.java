package com.fivucsas.identity.application.port.output;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Store port for the authors-only trial (V90).
 *
 * <p>Explicit, narrow operations so the two writers — the trial service
 * (session/plan/finish) and the MFA verdict recorder (decision fields) — never
 * read-modify-write a shared document and lose each other's update. The adapter
 * owns all JPA mapping; the application layer sees immutable records only.
 */
public interface AuthorTrialStorePort {

    /** One pseudonymous participant bound to a test-tenant account. */
    record Participant(UUID id, UUID tenantId, String code, UUID userId, Instant enrolledAt) {}

    /** One slot of a shuffled round. */
    record PlanSlot(UUID id, int roundNo, int position, String challenge) {}

    /** Fields written when an attempt is created. */
    record NewAttempt(UUID tenantId,
                      String participantCode,
                      String mode,
                      String targetCode,
                      String instrument,
                      String instrumentPreset,
                      String plannedChallenge,
                      String challenge,
                      int roundNo,
                      int position,
                      UUID planEntryId,
                      boolean binding,
                      String difficulty,
                      int challengeCount,
                      String livenessMode,
                      UUID mfaSessionId,
                      Instant startedAt,
                      String deviceJson,
                      String envJson,
                      String webVersion,
                      String apiVersion,
                      String bioVersion) {}

    /** Full attempt row as exported. */
    record Attempt(UUID id,
                   UUID tenantId,
                   String participantCode,
                   String mode,
                   String targetCode,
                   String instrument,
                   String instrumentPreset,
                   String plannedChallenge,
                   String challenge,
                   int roundNo,
                   int position,
                   UUID planEntryId,
                   boolean binding,
                   String difficulty,
                   int challengeCount,
                   String livenessMode,
                   String traceContract,
                   UUID mfaSessionId,
                   String puzzleSessionId,
                   Instant startedAt,
                   Instant decidedAt,
                   String outcome,
                   String livenessVerdict,
                   String identityVerdict,
                   String stepOutcome,
                   String failureReason,
                   Double identityScore,
                   Double identityDistance,
                   Double identityThreshold,
                   Integer clientLatencyMs,
                   int challengesSubmitted,
                   String lastChallengeVerdict,
                   String lastChallengeReason,
                   String deviceJson,
                   String envJson,
                   String webVersion,
                   String apiVersion,
                   String bioVersion) {}

    /** Decision fields recorded from the real MFA step. */
    record Verdicts(String livenessVerdict,
                    String identityVerdict,
                    String stepOutcome,
                    String failureReason,
                    Double identityScore,
                    Double identityDistance,
                    Double identityThreshold,
                    Instant at) {}

    /** Technical finish status supplied by the page. */
    record Finish(String clientOutcome,
                  String failureReason,
                  Integer clientLatencyMs,
                  String deviceJson,
                  String envJson,
                  Instant at) {}

    record DeletionCounts(int attempts, int planEntries, int participants) {}

    List<Participant> participants(UUID tenantId);

    Optional<Participant> participant(UUID tenantId, String participantCode);

    void markEnrolled(UUID participantId, Instant at);

    /** Locks the first free slot (transaction required); empty when the round is exhausted. */
    Optional<PlanSlot> lockNextFreeSlot(UUID tenantId, String participantCode, String mode);

    int maxRound(UUID tenantId, String participantCode, String mode);

    void createRound(UUID tenantId, String participantCode, String mode, int roundNo, List<String> challenges);

    void assignSlot(UUID slotId, UUID attemptId);

    UUID createAttempt(NewAttempt attempt);

    Optional<Attempt> attempt(UUID attemptId);

    Optional<Attempt> attemptByMfaSessionId(UUID mfaSessionId);

    Optional<Attempt> attemptByPuzzleSessionId(String puzzleSessionId);

    void recordPuzzleSession(UUID attemptId, String puzzleSessionId, String traceContract, String issuedChallenge);

    void recordChallengeSubmit(String puzzleSessionId, String verdict, String reason);

    void recordVerdicts(UUID mfaSessionId, Verdicts verdicts);

    void recordAccept(UUID mfaSessionId, Instant at);

    void recordFinish(UUID attemptId, Finish finish);

    List<Attempt> attemptsForExport(UUID tenantId, int limit);

    DeletionCounts deleteForTenant(UUID tenantId);
}