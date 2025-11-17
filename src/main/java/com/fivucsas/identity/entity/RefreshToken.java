package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, unique = true, length = 500)
    private String token;

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
