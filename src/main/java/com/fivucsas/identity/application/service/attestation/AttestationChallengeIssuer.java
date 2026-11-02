package com.fivucsas.identity.application.service.attestation;

import com.fivucsas.identity.application.port.output.AttestationChallengePort;
import com.fivucsas.identity.application.service.AttestedBindingPolicy;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * Issues the single-use attestation challenge returned with a puzzle session
 * CREATE when the attested puzzle binding applies
 * ({@code docs/ATTESTED_PUZZLE_BINDING.md} §4.1): 32 random bytes from
 * {@link SecureRandom}, stored keyed by the bio puzzle session id and bound to the
 * creating MFA session, with the puzzle session's lifetime.
 */
@Component
public class AttestationChallengeIssuer {

    /** Nonce length in bytes. */
    public static final int NONCE_BYTES = 32;
    /** Lifetime: bio puzzle sessions live 300 s; the nonce never outlives them. */
    public static final Duration CHALLENGE_TTL = Duration.ofSeconds(300);

    private final AttestedBindingPolicy policy;
    private final AttestationChallengePort store;
    private final SecureRandom random = new SecureRandom();

    public AttestationChallengeIssuer(AttestedBindingPolicy policy, AttestationChallengePort store) {
        this.policy = policy;
        this.store = store;
    }

    /** Whether CREATE must issue a challenge for this tenant/step. */
    public boolean applies(UUID tenantId, boolean identityBindingStep) {
        return identityBindingStep && policy.isEnabledFor(tenantId);
    }

    /**
     * Generates and stores a nonce; returns it base64url-encoded without padding.
     *
     * @throws IllegalStateException when the store is unavailable (caller fails closed)
     */
    public String issue(String puzzleSessionId, UUID mfaSessionId) {
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        store.store(puzzleSessionId, Optional.ofNullable(mfaSessionId)
                .orElseThrow(() -> new IllegalStateException("MFA session has no id")), nonce, CHALLENGE_TTL);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
    }
}
