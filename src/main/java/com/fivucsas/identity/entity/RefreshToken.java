package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * JPA-safe equality by immutable id (P2.10). Replaces the Lombok {@code @Data}
     * default which included {@code user} (a lazy {@code @ManyToOne}) — that would
     * trigger proxy initialization on every {@code equals}/{@code hashCode} and
     * could StackOverflow via the back-reference. See {@link User#equals(Object)}
     * for the full rationale.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken other)) return false;
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return RefreshToken.class.hashCode();
    }

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, unique = true, length = 500)
    private String token;

    /**
     * SHA-256 of the refresh-token secret-half (P1-1, 2026-05-02).
     *
     * <p>The wire token has the form {@code <id>.<secret>}; only the digest
     * of the secret-half is persisted. Nullable for backward compatibility
     * with rows minted before this PR — those rows still satisfy reads via
     * the plaintext {@link #token} column. New rows always populate this
     * column. The plaintext column will be dropped in a follow-up migration
     * after operator soak.
     *
     * <p>See {@link com.fivucsas.identity.service.RefreshTokenHasher} and
     * {@code SECURITY_REVIEW_2026-05-01.md} §P1-1.
     */
    @Column(name = "token_secret_hash")
    private byte[] tokenSecretHash;

    /**
     * Rotation-family identifier (Sec-P2 #6, 2026-04-29).
     *
     * <p>All refresh tokens minted from a single initial login share one
     * family_id, propagated through every rotation. When the application
     * detects replay of a revoked token, every row sharing this family_id
     * is revoked at once — RFC 6749 §10.4 + OAuth 2.0 Security BCP §4.13.
     * See {@code RefreshTokenService.rotateRefreshToken}.
     */
    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(nullable = false)
    private Instant expiryDate;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column
    private Instant revokedAt;

    @Column(name = "is_revoked")
    @Builder.Default
    private boolean isRevoked = false;

    @Column(length = 45)
    private String ipAddress;

    @Column(length = 500)
    private String userAgent;

    public boolean isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }

    public void revoke() {
        this.isRevoked = true;
        this.revokedAt = Instant.now();
    }
}
