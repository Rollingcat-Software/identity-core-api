package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Junction entity mapping an email domain (e.g. "marmara.edu.tr") to the
 * tenant that owns it.
 *
 * <p>Used on registration to auto-assign a new user to their organisation's
 * tenant based on the domain part of their email address, and by the tenant
 * admin panel to manage the list of owned domains.</p>
 *
 * <p>Invariants (enforced by V44 schema):</p>
 * <ul>
 *   <li>A domain belongs to AT MOST one tenant (UNIQUE index on email_domain).</li>
 *   <li>A tenant has AT MOST one {@code is_primary=true} row (partial UNIQUE).</li>
 *   <li>Email domain is stored lowercase and does not contain '@' (CHECK).</li>
 * </ul>
 */
@Entity
@Table(name = "tenant_email_domains")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class TenantEmailDomain {

    @EmbeddedId
    private TenantEmailDomainId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("tenantId")
    @JoinColumn(name = "tenant_id", insertable = false, updatable = false)
    private Tenant tenant;

    @Column(name = "is_primary", nullable = false)
    @Builder.Default
    private boolean isPrimary = false;

    /**
     * Domain-ownership gate (V63). FALSE until ownership is proven (DNS-TXT
     * verification — Round 2 — or SUPER_ADMIN approval). Only verified domains
     * auto-bind new registrants and satisfy {@code enforce_domain_matching}.
     * Self-service onboarding claims a domain as {@code verified=false}.
     */
    @Column(name = "verified", nullable = false)
    @Builder.Default
    private boolean verified = false;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    // ========== Business Methods ==========

    public UUID getTenantId() {
        return id != null ? id.getTenantId() : null;
    }

    public String getEmailDomain() {
        return id != null ? id.getEmailDomain() : null;
    }

    public void markPrimary() {
        this.isPrimary = true;
    }

    public void clearPrimary() {
        this.isPrimary = false;
    }

    /** Flips this domain to verified (DNS-TXT verification or admin approval). */
    public void markVerified() {
        this.verified = true;
    }

    /**
     * Factory — normalises the domain to lowercase and trims whitespace.
     *
     * <p>Defaults {@code verified=false}: callers that provision a trusted
     * domain (e.g. ROOT/admin CRUD) should call {@link #markVerified()} or use
     * {@link #create(UUID, String, boolean, boolean)}. Self-service onboarding
     * keeps the default (unverified).</p>
     */
    public static TenantEmailDomain create(UUID tenantId, String emailDomain, boolean isPrimary) {
        return create(tenantId, emailDomain, isPrimary, false);
    }

    /** Factory with explicit verified state. */
    public static TenantEmailDomain create(UUID tenantId, String emailDomain, boolean isPrimary, boolean verified) {
        return TenantEmailDomain.builder()
            .id(TenantEmailDomainId.of(tenantId, emailDomain))
            .isPrimary(isPrimary)
            .verified(verified)
            .build();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TenantEmailDomain other)) return false;
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "TenantEmailDomain{" +
            "tenantId=" + getTenantId() +
            ", emailDomain='" + getEmailDomain() + '\'' +
            ", isPrimary=" + isPrimary +
            '}';
    }
}
