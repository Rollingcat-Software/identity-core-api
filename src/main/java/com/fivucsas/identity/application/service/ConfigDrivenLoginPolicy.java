package com.fivucsas.identity.application.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Feature gate for the config-driven login engine (task #16, operator
 * reversibility directive 2026-05-30).
 *
 * <p>The behavior change in {@link AuthenticateUserService} (dropping the hard
 * pre-flow password gate) and the usernameless-into-flow handoff
 * ({@link UsernamelessLoginFlowService}) can "bang" the entire login path, so
 * it must be instantly revertible WITHOUT a redeploy/rollback. This policy is
 * the single source of truth for whether the new model applies to a given
 * tenant:
 *
 * <ul>
 *   <li><b>OFF (default)</b> — behavior is byte-identical to the legacy
 *       password-first login: the hard password gate stays, and usernameless
 *       entry points mint tokens directly. Reverting a bad rollout = set the
 *       flag back to false (no rebuild).</li>
 *   <li><b>Global ON</b> ({@code app.auth.config-driven-login=true}) — the new
 *       config-driven model applies to every tenant.</li>
 *   <li><b>Per-tenant canary</b>
 *       ({@code app.auth.config-driven-login-tenants=<uuid>,<uuid>}) — the new
 *       model applies ONLY to the listed tenants even when the global flag is
 *       false, so one tenant can be canaried in production before flipping the
 *       master switch.</li>
 * </ul>
 *
 * <p>Both knobs are plain {@code @Value} env-backed properties (mirrors
 * {@code app.identity.*}, {@code app.onboarding.*}, {@code app.webauthn.*}); no
 * DB write / migration is needed to flip them, keeping the kill-switch fast and
 * blast-radius minimal.
 */
@Component
@Slf4j
public class ConfigDrivenLoginPolicy {

    private final boolean globallyEnabled;
    private final Set<UUID> canaryTenantIds;

    public ConfigDrivenLoginPolicy(
            @Value("${app.auth.config-driven-login:false}") boolean globallyEnabled,
            @Value("${app.auth.config-driven-login-tenants:}") String canaryTenants) {
        this.globallyEnabled = globallyEnabled;
        this.canaryTenantIds = parseTenantIds(canaryTenants);
        log.info("Config-driven login engine: globallyEnabled={}, canaryTenantCount={}",
                globallyEnabled, canaryTenantIds.size());
    }

    /**
     * True when the config-driven login engine should drive {@code tenantId}.
     * Defaults to false (legacy behavior) for every tenant unless the global
     * flag is on or the tenant is explicitly canaried.
     */
    public boolean isEnabledFor(UUID tenantId) {
        if (globallyEnabled) {
            return true;
        }
        return tenantId != null && canaryTenantIds.contains(tenantId);
    }

    /**
     * The GLOBAL master switch state, independent of any tenant. Used by the
     * platform (no-tenant) login surface — the dashboard's own cross-tenant login
     * — which has no single tenant to consult, so it follows the global flag only
     * (per-tenant canary is irrelevant to it).
     */
    public boolean isGloballyEnabled() {
        return globallyEnabled;
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
                log.warn("Ignoring invalid tenant UUID in app.auth.config-driven-login-tenants: '{}'", token);
            }
        }
        return ids;
    }
}
