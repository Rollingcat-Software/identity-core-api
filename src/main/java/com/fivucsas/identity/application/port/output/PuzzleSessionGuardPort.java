package com.fivucsas.identity.application.port.output;

import java.time.Duration;
import java.util.Optional;

/**
 * Output port for the identity-side guards around bio puzzle sessions
 * (puzzle contract v2 security review, findings S2 + S5).
 *
 * <ul>
 *   <li><b>Create cap (S2).</b> One MFA session token may create only a bounded
 *       number of bio puzzle sessions. Without it a client could create a fresh
 *       bio session after every 3 failed attempts and so reset bio's per-session
 *       attempt cap indefinitely.</li>
 *   <li><b>Trace-contract record (S5).</b> At CREATE, bio advertises the session's
 *       trace contract ({@code trace_contract: "v2"} or absent = v1). Recording it
 *       server-side lets the verdict handler fail a binding-required v2 step closed
 *       unless bio confirms {@code binding_checked: true}, while a session bio itself
 *       created as v1 (bio flag OFF) keeps its legacy behaviour.</li>
 * </ul>
 */
public interface PuzzleSessionGuardPort {

    /** Contract value recorded for a session bio created as legacy v1. */
    String CONTRACT_V1 = "v1";
    /** Contract value recorded for a session bio created as v2. */
    String CONTRACT_V2 = "v2";

    /**
     * Atomically increments the number of bio puzzle sessions created under one
     * MFA session and returns the new count (1 for the first create).
     *
     * @param mfaSessionKey stable key of the MFA session (its id)
     * @param ttl           how long the counter lives (at least the MFA session TTL)
     * @throws IllegalStateException when the backing store is unavailable; callers
     *                               fail CLOSED (no bio session is created)
     */
    long incrementCreates(String mfaSessionKey, Duration ttl);

    /** Records the trace contract bio advertised for {@code puzzleSessionId} (best effort). */
    void recordTraceContract(String puzzleSessionId, String contract, Duration ttl);

    /**
     * The trace contract recorded at CREATE, or empty when unknown (never recorded,
     * expired, or the store is unavailable). Callers treat empty as "not v1".
     */
    Optional<String> traceContractFor(String puzzleSessionId);
}
