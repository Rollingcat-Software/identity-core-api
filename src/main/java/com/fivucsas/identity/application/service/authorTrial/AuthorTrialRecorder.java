package com.fivucsas.identity.application.service.authorTrial;

import java.util.Optional;
import java.util.UUID;

/**
 * Side-effect-only hook used by the REAL MFA machinery to record a trial
 * attempt's decision. Every method is a no-op by default so the handler and
 * the MFA orchestrator can depend on this without changing any non-trial
 * behaviour; {@link AuthorTrialRecorderImpl} overrides the methods and is
 * active only when the trial surface is enabled for the session's tenant.
 *
 * <p>Implementations MUST NOT throw and MUST NOT affect the authentication
 * result: recording is observation, never a gate.
 */
public interface AuthorTrialRecorder {

    /** No-op instance for legacy constructors and tests. */
    AuthorTrialRecorder NO_OP = new AuthorTrialRecorder() {
    };

    /** The trial context of an MFA session, when one exists. */
    record TrialSession(UUID attemptId, String challenge, String puzzleSessionId) {}

    /** Empty for every non-trial MFA session (and while the surface is disabled). */
    default Optional<TrialSession> trialSession(UUID mfaSessionId) {
        return Optional.empty();
    }

    /** The PUZZLE step failed before/at a gate (liveness or identity). */
    default void stepFailed(UUID mfaSessionId, UUID tenantId,
                            String livenessVerdict, String identityVerdict, String reason) {
    }

    /** The PUZZLE step passed; scores are from bio's embedding match when binding ran. */
    default void stepPassed(UUID mfaSessionId, UUID tenantId, boolean binding,
                            Double identityScore, Double identityDistance, Double identityThreshold) {
    }

    /** The MFA session completed and minted tokens: the authoritative accept. */
    default void accepted(UUID mfaSessionId, UUID tenantId) {
    }

    /** A trial puzzle session was created; records session id, contract and issued action. */
    default void puzzleSessionCreated(UUID attemptId, String puzzleSessionId,
                                      String traceContract, String issuedChallenge) {
    }

    /** A per-challenge SUBMIT was answered by bio. */
    default void challengeSubmitted(String puzzleSessionId, boolean verified, String reasonCode) {
    }
}