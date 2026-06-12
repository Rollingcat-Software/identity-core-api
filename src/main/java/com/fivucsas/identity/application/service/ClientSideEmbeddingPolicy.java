package com.fivucsas.identity.application.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Feature gate for the CLIENT-SIDE-EMBEDDING face path (sub-project A, Phase 5
 * — "world-ready" privacy: the Facenet512 embedding is computed in the browser
 * so the raw face image never leaves the device).
 *
 * <p>When this policy is ON and a FACE step / enrollment payload carries a
 * precomputed {@code embedding} (512 floats) instead of an {@code image},
 * Identity Core forwards to the biometric-processor's
 * {@code POST /verify-embedding} / {@code POST /enroll-embedding} endpoints.
 * When OFF (the default) the legacy image path
 * ({@code /verify} / {@code /enroll}) is used and behaviour is byte-identical to
 * before — so a bad rollout reverts by flipping the env flag, WITHOUT a redeploy.
 * This mirrors {@link ConfigDrivenLoginPolicy} exactly (operator reversibility
 * directive): security-critical core paths ship flag-gated, default OFF (legacy).
 *
 * <ul>
 *   <li><b>OFF (default)</b> — legacy image path for every tenant.</li>
 *   <li><b>Global ON</b> ({@code app.auth.client-side-embedding=true}) — the
 *       embedding path applies to every tenant whose payload carries an
 *       embedding.</li>
 *   <li><b>Per-tenant canary</b>
 *       ({@code app.auth.client-side-embedding-tenants=<uuid>,<uuid>}) — the
 *       embedding path applies ONLY to the listed tenants even when the global
 *       flag is false, so one tenant can be canaried in production before the
 *       master switch is flipped.</li>
 * </ul>
 *
 * <p>Both knobs are plain {@code @Value} env-backed properties (mirrors
 * {@code app.auth.config-driven-login*}); no DB write / migration is needed to
 * flip them, keeping the kill-switch fast and the blast radius minimal.
 *
 * <p><b>SECURITY:</b> the embedding path carries NO image, therefore the
 * biometric-processor cannot run server-side liveness / anti-spoof on a raw
 * frame. An embedding-only FACE factor MUST be paired with a separate liveness
 * factor (puzzle / passive) in the auth flow — that enforcement is delivered by
 * sub-projects B/C; this policy only governs WHERE the embedding is matched.
 */
@Component
@Slf4j
public class ClientSideEmbeddingPolicy {

    private final boolean globallyEnabled;
    private final Set<UUID> canaryTenantIds;

    public ClientSideEmbeddingPolicy(
            @Value("${app.auth.client-side-embedding:false}") boolean globallyEnabled,
            @Value("${app.auth.client-side-embedding-tenants:}") String canaryTenants) {
        this.globallyEnabled = globallyEnabled;
        this.canaryTenantIds = parseTenantIds(canaryTenants);
        log.info("Client-side-embedding face path: globallyEnabled={}, canaryTenantCount={}",
                globallyEnabled, canaryTenantIds.size());
    }

    /**
     * The GLOBAL master switch state, independent of any tenant. The default
     * (false) means the legacy image path is used everywhere.
     */
    public boolean isEnabled() {
        return globallyEnabled;
    }

    /**
     * True when the client-side-embedding path should drive FACE for
     * {@code tenantId}. Defaults to false (legacy image path) for every tenant
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
     * null/non-UUID) tenant id as a {@code String} — the enroll/verify command
     * shape. Uses the GLOBAL master switch, falling back to the per-tenant canary
     * list only when the id parses to a UUID. A null / blank / non-UUID tenant id
     * is enabled ONLY under the global switch, never via the canary list (a
     * malformed id cannot match a canary entry, and must not silently widen the
     * rollout). This is the single source of truth for the enroll routing gate —
     * {@code EnrollBiometricService} and {@code BiometricController} both delegate
     * here so the controller's fail-closed reject and the service's routing
     * decision can never disagree.
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
                log.warn("Ignoring invalid tenant UUID in app.auth.client-side-embedding-tenants: '{}'", token);
            }
        }
        return ids;
    }
}
