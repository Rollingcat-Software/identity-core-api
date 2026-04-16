package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * OAuth 2.0 / OIDC registered client entity.
 *
 * Represents a third-party or first-party application that can initiate
 * OAuth 2.0 authorization flows against the identity service.
 */
@Entity
@Table(name = "oauth2_clients", indexes = {
    @Index(name = "idx_oauth2_clients_client_id", columnList = "client_id", unique = true),
    @Index(name = "idx_oauth2_clients_tenant_id", columnList = "tenant_id")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class OAuth2Client {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "client_id", nullable = false, unique = true, length = 128)
    private String clientId;

    @Column(name = "client_secret", nullable = false, length = 255)
    private String clientSecret;

    @Column(name = "client_name", nullable = false, length = 255)
    private String clientName;

    /**
     * JSON array of allowed redirect URIs.
     * Example: ["https://app.example.com/callback", "http://localhost:3000/callback"]
     */
    @Column(name = "redirect_uris", nullable = false, columnDefinition = "TEXT")
    private String redirectUris;

    /**
     * Space-separated list of allowed scopes.
     * Example: "openid profile email"
     */
    @Column(name = "allowed_scopes", nullable = false, length = 500)
    @Builder.Default
    private String allowedScopes = "openid profile email";

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    // ========== Business Methods ==========

    /**
     * Checks if the given redirect URI is allowed for this client.
     *
     * Matching rules:
     * 1. HTTPS and custom-scheme URIs (e.g. "com.acme://auth") — exact string match.
     * 2. Loopback URIs per RFC 8252 §7.3 — a registered "http://127.0.0.1/cb" (or
     *    "http://localhost/cb") matches any port supplied by a native app, because
     *    ephemeral ports are chosen at runtime. Path + scheme + host must still match.
     */
    public boolean isRedirectUriAllowed(String uri) {
        if (redirectUris == null || uri == null) return false;
        // Fast path — exact JSON-embedded literal match
        if (redirectUris.contains("\"" + uri + "\"")) return true;
        return matchesLoopbackRegistration(uri);
    }

    private boolean matchesLoopbackRegistration(String uri) {
        try {
            URI incoming = new URI(uri);
            if (!"http".equalsIgnoreCase(incoming.getScheme())) return false;
            String incomingHost = incoming.getHost();
            if (!"127.0.0.1".equals(incomingHost) && !"localhost".equals(incomingHost)) return false;
            String incomingPath = incoming.getPath() == null ? "" : incoming.getPath();

            for (String candidate : splitRegisteredRedirectUris()) {
                URI reg;
                try {
                    reg = new URI(candidate);
                } catch (URISyntaxException e) {
                    continue;
                }
                if (!"http".equalsIgnoreCase(reg.getScheme())) continue;
                String regHost = reg.getHost();
                if (!incomingHost.equals(regHost)) continue;
                String regPath = reg.getPath() == null ? "" : reg.getPath();
                if (incomingPath.equals(regPath)) return true;
            }
        } catch (URISyntaxException ignored) {
        }
        return false;
    }

    private List<String> splitRegisteredRedirectUris() {
        String raw = redirectUris.replaceAll("^\\[|\\]$", "").replace("\"", "");
        if (raw.isEmpty()) return List.of();
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    /**
     * Checks if the given scope is allowed for this client.
     */
    public boolean isScopeAllowed(String scope) {
        if (allowedScopes == null || scope == null) return false;
        String[] scopes = allowedScopes.split("\\s+");
        for (String s : scopes) {
            if (s.equals(scope)) return true;
        }
        return false;
    }

    /**
     * Checks if all requested scopes are allowed.
     */
    public boolean areAllScopesAllowed(String requestedScopes) {
        if (requestedScopes == null || requestedScopes.isBlank()) return true;
        String[] requested = requestedScopes.split("\\s+");
        for (String scope : requested) {
            if (!isScopeAllowed(scope)) return false;
        }
        return true;
    }

    /**
     * Checks if the client registration has expired.
     */
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    /**
     * Checks if this client is valid (active, not expired, not revoked).
     */
    public boolean isValid() {
        return active && !isExpired() && revokedAt == null;
    }

    /**
     * Revokes this client permanently with an audit timestamp.
     */
    public void revoke() {
        this.active = false;
        this.revokedAt = Instant.now();
    }

    /**
     * Deactivates this client.
     */
    public void deactivate() {
        this.active = false;
    }

    /**
     * Activates this client.
     */
    public void activate() {
        this.active = true;
        this.revokedAt = null;
    }
}
