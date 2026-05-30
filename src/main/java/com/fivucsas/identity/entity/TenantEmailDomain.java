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

    // Read-only association for loading the owning tenant. The composite
    // @EmbeddedId (tenant_id + email_domain) is the writable key — callers set
    // it directly via TenantEmailDomain.create(tenantId, ...). @MapsId is NOT
    // used: it would force the id's tenantId to be derived from this (often
    // null on a fresh create) association, throwing "attempted to assign id
    // from null one-to-one property" on insert (broke onboarding + admin
    // add-domain, 2026-05-29). insertable/updatable=false keeps this purely a
    // read view; the embedded id owns the tenant_id column on write.
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", insertable = false, updatable = false)
    private Tenant tenant;

    @Column(name = "is_primary", nullable = false)
    @Builder.Default
    private boolean isPrimary = false;

    /**
     * Domain-ownership gate (V63). FALSE until ownership is proven (DNS-TXT
     * verification — Round 2 — or ROOT approval). Only verified domains
     * auto-bind new registrants and satisfy {@code enforce_domain_matching}.
     * Self-service onboarding claims a domain as {@code verified=false}.
     */
    @Column(name = "verified", nullable = false)
    @Builder.Default
    private boolean verified = false;

    /**
     * DNS-TXT verification secret (V64). The admin publishes
     * {@code fivucsas-domain-verification=<token>} as a TXT record under
     * {@code _fivucsas-verify.<domain>}; the {@code /verify} endpoint looks it
     * up and flips {@link #verified} on a match. NULL before a challenge is
     * requested and after the domain is verified (cleared on success).
     */
    @Column(name = "verification_token", length = 128)
    private String verificationToken;

    /** When the current {@link #verificationToken} was (re)issued (V64). */
    @Column(name = "verification_requested_at")
    private Instant verificationRequestedAt;

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
     * Records a freshly-issued DNS-TXT verification token and the issue time.
     * Used by the {@code POST .../{domain}/verification} challenge endpoint.
     */
    public void issueVerificationToken(String token) {
        this.verificationToken = token;
        this.verificationRequestedAt = Instant.now();
    }

    /**
     * Marks the domain verified via DNS-TXT and clears the now-spent token so
     * it cannot be reused. Called by the {@code /verify} endpoint on a match.
     */
    public void markVerifiedViaDns() {
        this.verified = true;
        this.verificationToken = null;
        this.verificationRequestedAt = null;
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
