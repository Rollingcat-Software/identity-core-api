package com.fivucsas.identity.application.service.authorTrial;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.UUID;

/**
 * The single gate of the public trial surface: feature flag + non-blank access
 * code + exactly one allow-listed tenant. The key is compared by SHA-256 digest
 * with {@link MessageDigest#isEqual} (constant time, equal-length inputs).
 */
@Component
@RequiredArgsConstructor
public class AuthorTrialAccessGuard {

    private final AuthorTrialProperties properties;

    /** True only when the surface is fully configured. */
    public boolean surfaceEnabled() {
        return properties.isEnabled()
                && properties.getAccessCode() != null
                && !properties.getAccessCode().isBlank()
                && properties.trialTenantId().isPresent();
    }

    /** Constant-time key check; false when the surface is disabled. */
    public boolean keyMatches(String presented) {
        if (!surfaceEnabled() || presented == null) {
            return false;
        }
        return MessageDigest.isEqual(sha256(presented), sha256(properties.getAccessCode()));
    }

    /** The configured trial tenant, or empty when not configured. */
    public Optional<UUID> trialTenantId() {
        return surfaceEnabled() ? properties.trialTenantId() : Optional.empty();
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}