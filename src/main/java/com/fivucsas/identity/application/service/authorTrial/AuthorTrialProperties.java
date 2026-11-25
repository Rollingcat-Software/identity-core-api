package com.fivucsas.identity.application.service.authorTrial;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Configuration of the authors-only trial surface (V90).
 *
 * <p>The whole surface is hidden (404) unless {@code enabled=true}, a non-blank
 * {@code access-code} is set AND exactly one tenant is allow-listed. The
 * single-tenant rule is deliberate: the page has no login and no tenant
 * selector, so an ambiguous allow-list is a configuration error, not a guess.
 */
@Component
@ConfigurationProperties(prefix = "app.author-trial")
@Getter
@Setter
public class AuthorTrialProperties {

    /** Default OFF: every endpoint answers 404. */
    private boolean enabled = false;

    /** Shared key; blank hides the surface. Compared in constant time. */
    private String accessCode = "";

    /** Comma-separated UUIDs; exactly one is required while the trial is active. */
    private List<String> tenantIds = new ArrayList<>();

    /** Version pin stamped into every attempt (deploy-time env). */
    private String apiVersion = "unknown";

    /** Fallback when the bio health probe cannot name a version. */
    private String fallbackBioVersion = "unknown";

    /** Hard ceiling on one export. */
    private int exportLimit = 50_000;

    /** Maximum sanitised device JSON size. */
    private int deviceMaxBytes = 4_096;

    /** Maximum sanitised environment JSON size. */
    private int envMaxBytes = 2_048;

    /** Parsed allow-list; malformed entries are ignored. */
    public Set<UUID> allowedTenantIds() {
        Set<UUID> ids = new LinkedHashSet<>();
        if (tenantIds == null) {
            return ids;
        }
        for (String raw : tenantIds) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            try {
                ids.add(UUID.fromString(raw.trim().toLowerCase(Locale.ROOT)));
            } catch (IllegalArgumentException ignored) {
                // A typo must not crash startup or widen the surface.
            }
        }
        return ids;
    }

    /** The one trial tenant, when the allow-list is exactly one valid UUID. */
    public Optional<UUID> trialTenantId() {
        Set<UUID> ids = allowedTenantIds();
        return ids.size() == 1 ? Optional.of(ids.iterator().next()) : Optional.empty();
    }
}