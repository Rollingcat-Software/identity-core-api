package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Entity representing API keys for programmatic access.
 *
 * API keys allow applications to authenticate without user credentials.
 * Keys are hashed for security (like passwords).
 *
 * Following principles:
 * - Security: Keys are hashed, never stored in plain text
 * - Auditability: Track last used time
 * - Flexibility: Support expiration and scopes
 */
@Entity
@Table(name = "api_keys")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(name = "key_hash", nullable = false, unique = true, length = 255)
    private String keyHash;

    @Column(nullable = false, length = 16)
    private String prefix;  // First 8 chars for identification

    @Column(columnDefinition = "text[]")
    private String[] scopes;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "is_active")
    @Builder.Default
    private boolean isActive = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /**
     * Checks if API key is expired.
     *
     * @return true if key is expired
     */
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    /**
     * Checks if API key is valid (active and not expired).
     *
     * @return true if key is valid
     */
    public boolean isValid() {
        return isActive && !isExpired();
    }

    /**
     * Updates last used timestamp.
     */
    public void recordUsage() {
        this.lastUsedAt = Instant.now();
    }

    /**
     * Revokes the API key.
     */
    public void revoke() {
        this.isActive = false;
    }
}
