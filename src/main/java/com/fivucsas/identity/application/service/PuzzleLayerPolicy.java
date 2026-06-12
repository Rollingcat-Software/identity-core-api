package com.fivucsas.identity.application.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Feature gate for the PUZZLE liveness layer (sub-project B, Phase 1 — PUZZLE
 * as a first-class auth-flow factor).
 *
 * <p>A PUZZLE step proves LIVENESS by re-scoring randomised challenge traces
 * server-side; identity is provided by an embedding match (later phases). This
 * policy gates whether PUZZLE is exposed as a selectable auth method and
 * considered valid in the login engine:
 *
 * <ul>
 *   <li><b>OFF (default)</b> — PUZZLE is absent from the {@code /auth-methods}
 *       catalog and is not offered in any login-config response. Behaviour is
 *       byte-identical to before. Revert a bad rollout by setting the flag back
 *       to false (no rebuild).</li>
 *   <li><b>Global ON</b> ({@code app.auth.puzzle-layer=true}) — PUZZLE is
 *       surfaced as a selectable login method for every tenant.</li>
 *   <li><b>Per-tenant canary</b>
 *       ({@code app.auth.puzzle-layer-tenants=<uuid>,<uuid>}) — PUZZLE is
 *       surfaced for the listed tenants only, even when the master switch is
 *       false, so one tenant can be canaried in production before the global
 *       flip.</li>
 * </ul>
 *
 * <p>Both knobs are plain {@code @Value} env-backed properties (mirrors
 * {@code app.auth.config-driven-login*} and
 * {@code app.auth.client-side-embedding*}); no DB write / migration is needed
 * to flip them, keeping the kill-switch fast and the blast radius minimal.
 */
@Component
@Slf4j
public class PuzzleLayerPolicy {

    private final boolean globallyEnabled;
    private final Set<UUID> canaryTenantIds;

    public PuzzleLayerPolicy(
            @Value("${app.auth.puzzle-layer:false}") boolean globallyEnabled,
            @Value("${app.auth.puzzle-layer-tenants:}") String canaryTenants) {
        this.globallyEnabled = globallyEnabled;
        this.canaryTenantIds = parseTenantIds(canaryTenants);
        log.info("Puzzle layer: globallyEnabled={}, canaryTenantCount={}",
                globallyEnabled, canaryTenantIds.size());
    }

    /**
     * The GLOBAL master switch state, independent of any tenant. The default
     * (false) means PUZZLE is hidden everywhere.
     */
    public boolean isGloballyEnabled() {
        return globallyEnabled;
    }

    /**
     * True when the PUZZLE layer should be surfaced for {@code tenantId}.
     * Defaults to false (PUZZLE hidden) for every tenant unless the global flag
     * is on or the tenant is explicitly canaried.
     */
    public boolean isEnabledFor(UUID tenantId) {
        if (globallyEnabled) {
            return true;
        }
        return tenantId != null && canaryTenantIds.contains(tenantId);
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
                log.warn("Ignoring invalid tenant UUID in app.auth.puzzle-layer-tenants: '{}'", token);
            }
        }
        return ids;
    }
}
