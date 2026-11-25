package com.fivucsas.identity.application.service.authorTrial;

import com.fivucsas.identity.application.port.output.AuthorTrialStorePort;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Verdicts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

/**
 * Active recorder of the trial attempt log. It never throws: every failure is
 * logged at warn and swallowed, because recording must never change an
 * authentication decision. It does nothing for a tenant that is not the
 * configured trial tenant, so the hook is inert for every other tenant even
 * while the surface is enabled.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorTrialRecorderImpl implements AuthorTrialRecorder {

    private final AuthorTrialStorePort store;
    private final AuthorTrialAccessGuard guard;

    private boolean applies(UUID tenantId) {
        return guard.trialTenantId().map(t -> t.equals(tenantId)).orElse(false);
    }

    @Override
    public java.util.Optional<TrialSession> trialSession(UUID mfaSessionId) {
        if (!guard.surfaceEnabled()) {
            return java.util.Optional.empty();
        }
        return store.attemptByMfaSessionId(mfaSessionId)
                .map(a -> new TrialSession(a.id(), a.challenge(), a.puzzleSessionId()));
    }

    @Override
    public void stepFailed(UUID mfaSessionId, UUID tenantId,
                           String livenessVerdict, String identityVerdict, String reason) {
        if (!applies(tenantId)) {
            return;
        }
        safe("stepFailed", () -> store.recordVerdicts(mfaSessionId,
                new Verdicts(livenessVerdict, identityVerdict, "fail", reason, null, null, null, Instant.now())));
    }

    @Override
    public void stepPassed(UUID mfaSessionId, UUID tenantId, boolean binding,
                           Double identityScore, Double identityDistance, Double identityThreshold) {
        if (!applies(tenantId)) {
            return;
        }
        safe("stepPassed", () -> store.recordVerdicts(mfaSessionId,
                new Verdicts("pass", binding ? "pass" : "na", "pass", null,
                        identityScore, identityDistance, identityThreshold, Instant.now())));
    }

    @Override
    public void accepted(UUID mfaSessionId, UUID tenantId) {
        if (!applies(tenantId)) {
            return;
        }
        safe("accepted", () -> store.recordAccept(mfaSessionId, Instant.now()));
    }

    @Override
    public void puzzleSessionCreated(UUID attemptId, String puzzleSessionId,
                                     String traceContract, String issuedChallenge) {
        if (!guard.surfaceEnabled()) {
            return;
        }
        safe("puzzleSessionCreated", () -> store.recordPuzzleSession(
                attemptId, puzzleSessionId, traceContract, issuedChallenge));
    }

    @Override
    public void challengeSubmitted(String puzzleSessionId, boolean verified, String reasonCode) {
        // Inert for every tenant while the surface is off: no query on the hot
        // PUZZLE submit path of an unrelated deployment.
        if (!guard.surfaceEnabled()) {
            return;
        }
        safe("challengeSubmitted", () -> store.recordChallengeSubmit(
                puzzleSessionId, verified ? "pass" : "fail", reasonCode));
    }

    private void safe(String operation, Runnable action) {
        try {
            action.run();
        } catch (RuntimeException e) {
            log.warn("author-trial recorder {} failed (ignored): {}", operation, e.getMessage());
        }
    }
}