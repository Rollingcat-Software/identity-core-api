package com.fivucsas.identity.application.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Feature gate for the ATTESTED puzzle binding
 * ({@code docs/ATTESTED_PUZZLE_BINDING.md}).
 *
 * <p>When enabled for a tenant, a PUZZLE step that also matches face identity
 * ({@code puzzleConfig.alsoMatchFaceIdentity}) REQUIRES a valid hardware key
 * attestation bundle: the puzzle session CREATE returns a single-use
 * {@code attestation_challenge}, and the step fails closed unless the client
 * presents an attestation chain over that challenge plus a signature over the
 * canonical (session, nonce, embedding, trace digest, binding frame) payload.
 *
 * <ul>
 *   <li><b>OFF (default)</b> — no challenge is issued and the attestation bundle is
 *       ignored; behaviour is byte-identical to before.</li>
 *   <li><b>Global ON</b> ({@code app.auth.attested-binding=true}).</li>
 *   <li><b>Per-tenant canary</b> ({@code app.auth.attested-binding-tenants=<uuid>,...}).</li>
 * </ul>
 *
 * <p>Because a browser cannot produce hardware attestation, turning this on for a
 * tenant whose identity-bound PUZZLE step is used from the web makes that step
 * fail closed on the web. That is the intended trade-off: enable it only for
 * tenants whose bound puzzle runs in the native app.
 */
@Component
@Slf4j
public class AttestedBindingPolicy {

    private final boolean globallyEnabled;
    private final Set<UUID> canaryTenantIds;

    public AttestedBindingPolicy(
            @Value("${app.auth.attested-binding:false}") boolean globallyEnabled,
            @Value("${app.auth.attested-binding-tenants:}") String canaryTenants) {
        this.globallyEnabled = globallyEnabled;
        this.canaryTenantIds = parseTenantIds(canaryTenants);
        log.info("Attested puzzle binding: globallyEnabled={}, canaryTenantCount={}",
                globallyEnabled, canaryTenantIds.size());
    }

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
                log.warn("Ignoring invalid tenant UUID in app.auth.attested-binding-tenants: '{}'", token);
            }
        }
        return ids;
    }
}
