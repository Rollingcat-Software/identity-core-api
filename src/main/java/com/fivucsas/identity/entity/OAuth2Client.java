package com.fivucsas.identity.entity;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
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

    /**
     * True for traditional server-side web apps that can hold a client_secret.
     * False for public clients (SPAs, native mobile, CLI) — these MUST use PKCE
     * S256 per RFC 7636 and cannot authenticate with a secret.
     */
    @Column(name = "confidential", nullable = false)
    @Builder.Default
    private boolean confidential = true;

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
     * <p>Matching rules:
     * <ol>
     *   <li>HTTPS and custom-scheme URIs (e.g. {@code com.acme://auth}) — exact
     *       string match.</li>
     *   <li>Loopback URIs per RFC 8252 §7.3 — a registered
     *       {@code http://127.0.0.1/cb} matches any port supplied by a native app
     *       because ephemeral ports are chosen at runtime. Scheme + host + path
     *       must match. Query string is ignored during matching (the attacker
     *       MUST NOT be able to smuggle arbitrary query params past registration).
     *       Only the IP literal 127.0.0.1 (or [::1]) is accepted; the hostname
     *       "localhost" is explicitly rejected because it resolves differently on
     *       different platforms and can be hijacked by DNS.</li>
     * </ol>
     */
    public boolean isRedirectUriAllowed(String uri) {
        if (redirectUris == null || uri == null) return false;
        // Fast path — exact JSON-embedded literal match
        if (redirectUris.contains("\"" + uri + "\"")) return true;
        return matchesLoopbackRegistration(uri);
    }

    private static boolean isLoopbackHost(String host) {
        // RFC 8252 §7.3: loopback redirect URIs use IP literals only.
        // "localhost" is intentionally rejected — it is a DNS name that may
        // resolve to an external address in hostile network environments.
        return "127.0.0.1".equals(host) || "[::1]".equals(host) || "::1".equals(host);
    }

    private boolean matchesLoopbackRegistration(String uri) {
        try {
            URI incoming = new URI(uri);
            if (!"http".equalsIgnoreCase(incoming.getScheme())) return false;
            String incomingHost = incoming.getHost();
            if (!isLoopbackHost(incomingHost)) return false;
            String incomingPath = incoming.getPath() == null ? "" : incoming.getPath();

            String incomingQuery = incoming.getQuery();
            for (String candidate : splitRegisteredRedirectUris()) {
                URI reg;
                try {
                    reg = new URI(candidate);
                } catch (URISyntaxException e) {
                    continue;
                }
                if (!"http".equalsIgnoreCase(reg.getScheme())) continue;
                String regHost = reg.getHost();
                if (!isLoopbackHost(regHost)) continue;
                if (!incomingHost.equals(regHost)) continue;
                String regPath = reg.getPath() == null ? "" : reg.getPath();
                if (!incomingPath.equals(regPath)) continue;
                // Query-string safety: if registration has no query, reject any
                // incoming query (prevents ?attacker_param=x smuggling). If
                // registration has a query, it must match the incoming one byte-
                // for-byte. Port is intentionally not compared — RFC 8252 §7.3
                // explicitly permits ephemeral-port selection on loopback.
                String regQuery = reg.getQuery();
                if (java.util.Objects.equals(regQuery, incomingQuery)) return true;
            }
        } catch (URISyntaxException ignored) {
        }
        return false;
    }

    private static final ObjectMapper REDIRECT_URI_MAPPER = new ObjectMapper();
    private static final TypeReference<List<String>> STRING_LIST_TYPE = new TypeReference<>() {};

    /**
     * Parses the JSON-array-encoded redirect_uris column.
     *
     * <p>The previous implementation split on comma, which corrupted URIs containing
     * commas in query strings (e.g. {@code https://example.com/cb?next=a,b}). Jackson
     * parses the real JSON structure and preserves each URI intact.
     *
     * <p>Falls back to an empty list if the column contains malformed JSON so a bad
     * row doesn't break redirect validation for the whole request.
     */
    private List<String> splitRegisteredRedirectUris() {
        if (redirectUris == null || redirectUris.isBlank()) return List.of();
        try {
            return REDIRECT_URI_MAPPER.readValue(redirectUris, STRING_LIST_TYPE);
        } catch (Exception e) {
            return List.of();
        }
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
