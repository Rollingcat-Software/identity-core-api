package com.fivucsas.identity.application.port.output;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port: stores the single-use attestation challenge (nonce) issued with a
 * puzzle session for the attested puzzle binding
 * ({@code docs/ATTESTED_PUZZLE_BINDING.md}).
 *
 * <p>The nonce is keyed by the bio puzzle session id and bound to the MFA session
 * that created it, lives no longer than the puzzle session, and is CONSUMED
 * (read-and-delete) on the first verify attempt, successful or not.
 */
public interface AttestationChallengePort {

    /**
     * Stores {@code nonce} for {@code puzzleSessionId}, bound to {@code mfaSessionId}.
     *
     * @throws IllegalStateException when the store is unavailable (callers fail closed)
     */
    void store(String puzzleSessionId, UUID mfaSessionId, byte[] nonce, Duration ttl);

    /**
     * Atomically reads and deletes the challenge for {@code puzzleSessionId}.
     * Empty when it was never issued, already consumed, expired, or the store is
     * unavailable (all fail closed at the caller).
     */
    Optional<IssuedChallenge> consume(String puzzleSessionId);

    /** A consumed challenge: the MFA session it was issued to and the raw nonce. */
    record IssuedChallenge(UUID mfaSessionId, byte[] nonce) {
    }
}
