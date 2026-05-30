package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * REST controller for OAuth 2.0 client management (CRUD).
 *
 * Allows TENANT_ADMIN (and ROOT) users to register, list, view, delete,
 * and toggle status of OAuth2 clients within their tenant.
 *
 * <p>T-P1-SEC Fix B (2026-05-07): tightened from {@code isAuthenticated()} to
 * {@code @rbac.isTenantAdmin()} on every endpoint. Previously any
 * TENANT_MEMBER could mint OAuth2 client credentials for the tenant —
 * effectively a privilege-escalation primitive. {@code isTenantAdmin()} returns
 * true for TENANT_ADMIN, ROOT, and ROOT via {@code UserType.isAtLeast}.
 */
@RestController
@RequestMapping("/api/v1/oauth2/clients")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OAuth2 Clients", description = "CRUD endpoints for managing OAuth2 client applications")
@SecurityRequirement(name = "bearer-jwt")
public class OAuth2ClientController {

    private final OAuth2ClientRepositoryPort clientRepository;
    private final RbacAuthorizationService rbacService;
    private final PasswordEncoder passwordEncoder;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Grace window during which the prior client_secret remains valid
     * after rotation. 24h is a defensible default: long enough for a
     * typical CI/CD rollout to ship and warm caches, short enough that a
     * leaked old secret can't be re-used indefinitely. See
     * INVESTIGATION_MASTER_2026-05-07 §"developer/tenant constraints".
     */
    private static final java.time.Duration SECRET_ROTATION_GRACE = java.time.Duration.ofHours(24);

    // ========== Endpoints ==========

    /**
     * List all OAuth2 clients for the current tenant.
     */
    @GetMapping
    @PreAuthorize("@rbac.isTenantAdmin()")
    @Operation(summary = "List all OAuth2 clients for the authenticated user's tenant (admin only)")
    public ResponseEntity<List<OAuth2ClientResponse>> listClients() {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));
        UUID tenantId = currentUser.getTenant().getId();

        List<OAuth2ClientResponse> clients = clientRepository
                .findAllByTenantIdOrderByCreatedAtDesc(tenantId)
                .stream()
                .map(OAuth2ClientResponse::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok(clients);
    }

    /**
     * Register a new OAuth2 client. Returns client_id + plaintext client_secret ONCE.
     */
    @PostMapping
    @PreAuthorize("@rbac.isTenantAdmin()")
    @Operation(summary = "Register a new OAuth2 client (returns client_secret in plaintext once, admin only)")
    public ResponseEntity<OAuth2ClientCreatedResponse> registerClient(
            @Valid @RequestBody RegisterClientRequest request) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));
        UUID tenantId = currentUser.getTenant().getId();
        Tenant tenant = currentUser.getTenant();

        // Generate client_id and client_secret
        String clientId = "fiv_" + UUID.randomUUID().toString().replace("-", "");
        String rawSecret = generateSecureHex(64);
        String hashedSecret = passwordEncoder.encode(rawSecret);

        // Parse redirect URIs into JSON array
        List<String> uriList = Arrays.stream(request.getRedirectUris().split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
        String redirectUrisJson = "[" + uriList.stream()
                .map(u -> "\"" + u.replace("\"", "\\\"") + "\"")
                .collect(Collectors.joining(",")) + "]";

        // Space-separated scopes
        String scopes = String.join(" ", request.getScopes());

        OAuth2Client client = OAuth2Client.builder()
                .clientId(clientId)
                .clientSecret(hashedSecret)
                .clientName(request.getAppName().trim())
                .redirectUris(redirectUrisJson)
                .allowedScopes(scopes)
                .tenant(tenant)
                .active(true)
                .build();

        client = clientRepository.save(client);

        log.info("OAuth2 client registered: {} (tenant: {})", clientId, tenantId);

        return ResponseEntity.status(HttpStatus.CREATED).body(
                OAuth2ClientCreatedResponse.from(client, rawSecret));
    }

    /**
     * Get a single OAuth2 client by ID. Secret is masked.
     */
    @GetMapping("/{id}")
    @PreAuthorize("@rbac.isTenantAdmin()")
    @Operation(summary = "Get OAuth2 client details (secret is masked, admin only)")
    public ResponseEntity<OAuth2ClientResponse> getClient(@PathVariable UUID id) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));
        UUID tenantId = currentUser.getTenant().getId();

        OAuth2Client client = clientRepository.findById(id)
                .filter(c -> c.getTenant().getId().equals(tenantId))
                .orElseThrow(() -> new NoSuchElementException("Client not found"));

        return ResponseEntity.ok(OAuth2ClientResponse.fromEntity(client));
    }

    /**
     * Delete (hard-delete) an OAuth2 client.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("@rbac.isTenantAdmin()")
    @Operation(summary = "Delete an OAuth2 client (admin only)")
    public ResponseEntity<Void> deleteClient(@PathVariable UUID id) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));
        UUID tenantId = currentUser.getTenant().getId();

        OAuth2Client client = clientRepository.findById(id)
                .filter(c -> c.getTenant().getId().equals(tenantId))
                .orElseThrow(() -> new NoSuchElementException("Client not found"));

        clientRepository.delete(client);
        log.info("OAuth2 client deleted: {} (tenant: {})", client.getClientId(), tenantId);

        return ResponseEntity.noContent().build();
    }

    /**
     * Rotate an OAuth2 client's secret. Generates a fresh secret, persists
     * the bcrypt hash, and returns the plaintext secret ONCE. The previous
     * secret remains valid for 24h so deployed integrations can roll over
     * without downtime — see {@link OAuth2Client#rotateSecret} +
     * {@link OAuth2Client#isPreviousSecretValid}, and the V58 migration.
     *
     * <p>Admin-only — gated by {@code @rbac.isTenantAdmin()} like the rest
     * of this controller. Tenant scope is enforced exactly like the other
     * mutation endpoints (filter by tenantId from the authenticated user).</p>
     *
     * <p>INVESTIGATION_MASTER_2026-05-07 §"developer/tenant constraints":
     * "No client_secret rotation endpoint — operators must delete+recreate
     * clients, breaking active integrations."</p>
     */
    @PostMapping("/{id}/rotate-secret")
    @PreAuthorize("@rbac.isTenantAdmin()")
    @Operation(summary = "Rotate OAuth2 client_secret. New secret returned ONCE; old secret valid for 24h grace window. Admin only.")
    public ResponseEntity<OAuth2ClientCreatedResponse> rotateSecret(@PathVariable UUID id) {
        // Use the entity.User-free helper added for the hexagonal-boundary
        // ratchet (UserDomainBoundaryTest); we do not need anything from
        // the User entity beyond the tenant scope here.
        UUID tenantId = rbacService.getCurrentUserTenantId()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

        OAuth2Client client = clientRepository.findById(id)
                .filter(c -> c.getTenant().getId().equals(tenantId))
                .orElseThrow(() -> new NoSuchElementException("Client not found"));

        String newRawSecret = generateSecureHex(64);
        String newHashedSecret = passwordEncoder.encode(newRawSecret);

        client.rotateSecret(newHashedSecret, SECRET_ROTATION_GRACE);
        client = clientRepository.save(client);

        log.info("OAuth2 client_secret rotated: clientId={} (tenant: {}, grace: {})",
                client.getClientId(), tenantId, SECRET_ROTATION_GRACE);

        return ResponseEntity.ok(OAuth2ClientCreatedResponse.from(client, newRawSecret));
    }

    /**
     * Toggle active/inactive status of an OAuth2 client.
     */
    @PatchMapping("/{id}/status")
    @PreAuthorize("@rbac.isTenantAdmin()")
    @Operation(summary = "Toggle active/inactive status of an OAuth2 client (admin only)")
    public ResponseEntity<OAuth2ClientResponse> toggleStatus(
            @PathVariable UUID id,
            @Valid @RequestBody ToggleStatusRequest request) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));
        UUID tenantId = currentUser.getTenant().getId();

        OAuth2Client client = clientRepository.findById(id)
                .filter(c -> c.getTenant().getId().equals(tenantId))
                .orElseThrow(() -> new NoSuchElementException("Client not found"));

        if (request.isActive()) {
            client.activate();
        } else {
            client.deactivate();
        }
        client = clientRepository.save(client);

        log.info("OAuth2 client status changed: {} -> {} (tenant: {})",
                client.getClientId(), request.isActive() ? "ACTIVE" : "INACTIVE", tenantId);

        return ResponseEntity.ok(OAuth2ClientResponse.fromEntity(client));
    }

    // ========== Helpers ==========

    private static String generateSecureHex(int length) {
        byte[] bytes = new byte[length / 2];
        SECURE_RANDOM.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(length);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ========== Request / Response DTOs ==========

    @lombok.Data
    public static class RegisterClientRequest {
        @NotBlank(message = "App name is required")
        @Size(min = 1, max = 255, message = "App name must be between 1 and 255 characters")
        private String appName;

        @NotBlank(message = "At least one redirect URI is required")
        private String redirectUris;

        private List<String> scopes = List.of("openid");
    }

    @lombok.Data
    public static class ToggleStatusRequest {
        private boolean active;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class OAuth2ClientResponse {
        private String id;
        private String appName;
        private String clientId;
        private List<String> redirectUris;
        private List<String> scopes;
        private String status;
        private String createdAt;

        public static OAuth2ClientResponse fromEntity(OAuth2Client entity) {
            // Parse redirect URIs from JSON array
            List<String> uris = new ArrayList<>();
            if (entity.getRedirectUris() != null) {
                String raw = entity.getRedirectUris()
                        .replaceAll("^\\[|\\]$", "")
                        .replace("\"", "");
                if (!raw.isEmpty()) {
                    uris = Arrays.asList(raw.split(","));
                }
            }

            // Parse scopes from space-separated
            List<String> scopeList = entity.getAllowedScopes() != null
                    ? Arrays.asList(entity.getAllowedScopes().split("\\s+"))
                    : List.of();

            return OAuth2ClientResponse.builder()
                    .id(entity.getId().toString())
                    .appName(entity.getClientName())
                    .clientId(entity.getClientId())
                    .redirectUris(uris)
                    .scopes(scopeList)
                    .status(entity.isActive() ? "ACTIVE" : "INACTIVE")
                    .createdAt(entity.getCreatedAt() != null
                            ? entity.getCreatedAt().toString()
                            : Instant.now().toString())
                    .build();
        }
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class OAuth2ClientCreatedResponse {
        private String id;
        private String appName;
        private String clientId;
        private String clientSecret; // plaintext, shown ONCE
        private List<String> redirectUris;
        private List<String> scopes;
        private String status;
        private String createdAt;

        public static OAuth2ClientCreatedResponse from(OAuth2Client entity, String rawSecret) {
            OAuth2ClientResponse base = OAuth2ClientResponse.fromEntity(entity);
            return OAuth2ClientCreatedResponse.builder()
                    .id(base.getId())
                    .appName(base.getAppName())
                    .clientId(base.getClientId())
                    .clientSecret(rawSecret)
                    .redirectUris(base.getRedirectUris())
                    .scopes(base.getScopes())
                    .status(base.getStatus())
                    .createdAt(base.getCreatedAt())
                    .build();
        }
    }
}
