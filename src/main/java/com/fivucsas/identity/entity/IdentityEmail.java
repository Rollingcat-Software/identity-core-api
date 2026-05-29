package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * An email address a person ({@link Identity}) controls (Model A, Phase 1).
 *
 * <p>Introduced by V66. The email column carries a CASE-INSENSITIVE GLOBAL
 * UNIQUE (the {@code uq_identity_emails_lower_email} index on {@code lower(email)}),
 * so the same address can never anchor two identities. One identity may hold
 * several emails — the basis for Phase 2 account-linking.
 *
 * <p>Mirrors the {@link UserEnrollment} child-entity pattern: a LAZY
 * {@code @ManyToOne} to the parent plus a read-only raw {@code identity_id}
 * column so callers can read the FK without initializing the proxy.
 *
 * <p><b>NOT TENANT-SCOPED — DO NOT ADD {@code @Filter(tenantFilter)}.</b>
 * Platform-level, cross-tenant by design (no tenant_id). See {@link Identity}
 * and {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md}.
 */
@Entity
@Table(name = "identity_emails")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // For JPA
@AllArgsConstructor(access = AccessLevel.PRIVATE) // For Builder
@Builder
public class IdentityEmail {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IdentityEmail other)) return false;
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return IdentityEmail.class.hashCode();
    }

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "identity_id", nullable = false)
    private Identity identity;

    /**
     * Read-only view of the raw identity_id FK — lets callers surface the owning
     * identity's id without initializing the lazy {@link #identity} proxy.
     * insertable/updatable=false because the {@link #identity} association owns
     * this column.
     */
    @Column(name = "identity_id", insertable = false, updatable = false)
    private UUID identityId;

    @Column(nullable = false, length = 255)
    private String email;

    @Column(nullable = false)
    @Builder.Default
    private boolean verified = false;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
