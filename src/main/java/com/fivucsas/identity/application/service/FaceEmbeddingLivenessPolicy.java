package com.fivucsas.identity.application.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Liveness rule for the CLIENT-SIDE-EMBEDDING face path (gap Ü2).
 *
 * <p>A face embedding computed in the browser carries no frame, so the
 * biometric-processor cannot run presentation-attack detection on it. This
 * policy decides what Identity Core does with an embedding FACE submission that
 * is NOT backed by a liveness factor (a PUZZLE completed earlier in the same MFA
 * session), and with an embedding enrollment:
 *
 * <ul>
 *   <li><b>OFF</b> — behaviour from before this policy existed, no extra logging.</li>
 *   <li><b>AUDIT</b> (default) — behaviour unchanged, but every unpaired embedding
 *       login and every embedding enrollment is logged and audited, so the size of
 *       the gap can be measured before anything is enforced.</li>
 *   <li><b>ENFORCE</b> — an unpaired embedding login is re-routed to the image path
 *       (server-side passive PAD) when the request also carries an image, otherwise
 *       the client is asked for an image capture ({@code FACE_IMAGE_REQUIRED}); a
 *       self-service embedding enrollment is refused with 409
 *       {@code FACE_IMAGE_REQUIRED} so the client enrolls with an image.</li>
 * </ul>
 *
 * <p>Knobs (plain env-backed {@code @Value}s, no DB write, so the kill-switch is a
 * restart): {@code app.auth.face-embedding-liveness.mode}
 * ({@code APP_AUTH_FACE_EMBEDDING_LIVENESS_MODE}) and
 * {@code app.auth.face-embedding-liveness.enforce-tenants}
 * ({@code APP_AUTH_FACE_EMBEDDING_LIVENESS_ENFORCE_TENANTS}, comma-separated tenant
 * UUIDs that get ENFORCE while the global mode is AUDIT). Tenants are keyed and
 * parsed exactly as in {@link ClientSideEmbeddingPolicy}.
 *
 * <p>Fail direction: an unknown mode value parses to AUDIT (today's behaviour plus
 * logging), never to ENFORCE, so a typo can never lock users out. A malformed
 * tenant id in the canary list is skipped with a warning.
 */
@Component
@Slf4j
public class FaceEmbeddingLivenessPolicy {

    /** What to do with an embedding FACE factor that has no liveness evidence. */
    public enum Mode { OFF, AUDIT, ENFORCE }

    private final Mode globalMode;
    private final Set<UUID> enforceTenantIds;

    public FaceEmbeddingLivenessPolicy(
            @Value("${app.auth.face-embedding-liveness.mode:AUDIT}") String mode,
            @Value("${app.auth.face-embedding-liveness.enforce-tenants:}") String enforceTenants) {
        this.globalMode = parseMode(mode);
        this.enforceTenantIds = parseTenantIds(enforceTenants);
        log.info("Face-embedding liveness policy: mode={}, enforceTenantCount={}",
                globalMode, enforceTenantIds.size());
    }

    /** The global mode, independent of any tenant canary entry. */
    public Mode globalMode() {
        return globalMode;
    }

    /**
     * Effective mode for {@code tenantId}: ENFORCE when the global mode is ENFORCE
     * or the tenant is on the enforce list while the global mode is AUDIT;
     * otherwise the global mode. OFF stays OFF for every tenant (it is the full
     * kill-switch, so the canary list cannot override it).
     */
    public Mode modeFor(UUID tenantId) {
        if (globalMode == Mode.AUDIT && tenantId != null && enforceTenantIds.contains(tenantId)) {
            return Mode.ENFORCE;
        }
        return globalMode;
    }

    /**
     * String-tenant overload for the enrollment command shape. A null, blank or
     * non-UUID tenant id never matches the enforce list (it cannot widen the
     * rollout) and gets the global mode.
     */
    public Mode modeFor(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            return globalMode;
        }
        try {
            return modeFor(UUID.fromString(tenantId.trim()));
        } catch (IllegalArgumentException e) {
            return globalMode;
        }
    }

    static Mode parseMode(String raw) {
        if (raw == null || raw.isBlank()) {
            return Mode.AUDIT;
        }
        try {
            return Mode.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            log.warn("Unknown app.auth.face-embedding-liveness.mode '{}', using AUDIT", raw);
            return Mode.AUDIT;
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
                log.warn("Ignoring invalid tenant UUID in app.auth.face-embedding-liveness.enforce-tenants: '{}'",
                        token);
            }
        }
        return ids;
    }
}
