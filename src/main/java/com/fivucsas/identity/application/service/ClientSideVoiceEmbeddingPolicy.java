package com.fivucsas.identity.application.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Feature gate for the CLIENT-SIDE-EMBEDDING <b>voice</b> path (audit H3 —
 * GPU-less: the 256-d Resemblyzer speaker embedding is computed in the browser so
 * the raw audio never leaves the device, and the CPU-only server skips the
 * Resemblyzer forward pass).
 *
 * <p>This is the VOICE twin of {@link ClientSideEmbeddingPolicy} (face). It is a
 * <b>separate</b> class on purpose so the voice and face rollouts are independent
 * kill-switches — the voice client port is a documented scaffold whose browser
 * preprocessing is not yet validated to parity, so it must be flippable without
 * touching the (production-ready) face path.
 *
 * <p>When this policy is ON and a VOICE step / enrollment payload carries a
 * precomputed {@code embedding} (256 floats) instead of {@code voiceData},
 * Identity Core forwards to the biometric-processor's
 * {@code POST /voice/verify-embedding} / {@code POST /voice/enroll-embedding}
 * endpoints. When OFF (the default) the legacy audio path
 * ({@code /voice/verify} / {@code /voice/enroll}) is used and behaviour is
 * byte-identical to before — so a bad rollout reverts by flipping the env flag,
 * WITHOUT a redeploy.
 *
 * <ul>
 *   <li><b>OFF (default)</b> — legacy audio path for every tenant.</li>
 *   <li><b>Global ON</b> ({@code app.auth.client-side-voice-embedding=true}) — the
 *       embedding path applies to every tenant whose payload carries an
 *       embedding.</li>
 *   <li><b>Per-tenant canary</b>
 *       ({@code app.auth.client-side-voice-embedding-tenants=<uuid>,<uuid>}) — the
 *       embedding path applies ONLY to the listed tenants even when the global
 *       flag is false, so one tenant can be canaried in production before the
 *       master switch is flipped.</li>
 * </ul>
 *
 * <p>Both knobs are plain {@code @Value} env-backed properties; no DB write /
 * migration is needed to flip them, keeping the kill-switch fast and the blast
 * radius minimal.
 *
 * <p><b>SECURITY:</b> the embedding path carries NO audio, therefore the
 * biometric-processor cannot run its spectral-fingerprint replay check or any
 * live-capture proof. An embedding-only VOICE factor MUST be paired with a
 * separate liveness factor in the auth flow; this policy only governs WHERE the
 * embedding is matched.
 */
@Component
@Slf4j
public class ClientSideVoiceEmbeddingPolicy {

    private final boolean globallyEnabled;
    private final Set<UUID> canaryTenantIds;

    public ClientSideVoiceEmbeddingPolicy(
            @Value("${app.auth.client-side-voice-embedding:false}") boolean globallyEnabled,
            @Value("${app.auth.client-side-voice-embedding-tenants:}") String canaryTenants) {
        this.globallyEnabled = globallyEnabled;
        this.canaryTenantIds = parseTenantIds(canaryTenants);
        log.info("Client-side-embedding voice path: globallyEnabled={}, canaryTenantCount={}",
                globallyEnabled, canaryTenantIds.size());
    }

    /**
     * The GLOBAL master switch state, independent of any tenant. The default
     * (false) means the legacy audio path is used everywhere.
     */
    public boolean isEnabled() {
        return globallyEnabled;
    }

    /**
     * True when the client-side-embedding path should drive VOICE for
     * {@code tenantId}. Defaults to false (legacy audio path) for every tenant
     * unless the global flag is on or the tenant is explicitly canaried.
     */
    public boolean isEnabledForTenant(UUID tenantId) {
        if (globallyEnabled) {
            return true;
        }
        return tenantId != null && canaryTenantIds.contains(tenantId);
    }

    /**
     * String-tenant overload for call sites that hold the (optional, possibly
     * null/non-UUID) tenant id as a {@code String}. Uses the GLOBAL master switch,
     * falling back to the per-tenant canary list only when the id parses to a
     * UUID. A null / blank / non-UUID tenant id is enabled ONLY under the global
     * switch, never via the canary list (a malformed id cannot match a canary
     * entry, and must not silently widen the rollout).
     */
    public boolean isEnabledForTenant(String tenantId) {
        if (globallyEnabled) {
            return true;
        }
        if (tenantId == null || tenantId.isBlank()) {
            return false;
        }
        try {
            return isEnabledForTenant(UUID.fromString(tenantId.trim()));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static Set<UUID> parseTenantIds(String csv) {
        Set<UUID> ids = new LinkedHashSet<>();
        if (csv == null || csv.isBlank()) {
            return ids;
        }
        for (String raw : csv.split(",")) {
            String token = raw.trim();
            if (token.isEmpty()) {
                continue;
            }
            try {
                ids.add(UUID.fromString(token.toLowerCase(Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                // A typo in the canary list must NOT crash startup or silently
                // widen the rollout — skip the bad token with a warning.
                log.warn("Ignoring invalid tenant UUID in app.auth.client-side-voice-embedding-tenants: '{}'", token);
            }
        }
        return ids;
    }
}
