package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Per-(identity, tenant[, method]) biometric CONSENT ledger (Model A, Phase 3).
 *
 * <p>A person (identity) holds ONE biometric template (Model A). A tenant may
 * VERIFY a probe against that template ONLY when the person has granted consent
 * for that tenant. The api orchestration layer reads this ledger to decide
 * whether a verify in tenant T may be routed to the person's CANONICAL
 * enrollment (the membership where they actually enrolled) under a DIFFERENT
 * membership of the SAME identity. The raw template/embedding is never shared —
 * the tenant only ever receives a verify DECISION. See
 * {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md} (Phase 3).
 *
 * <p><b>NOT TENANT-SCOPED — DO NOT ADD {@code @Filter(tenantFilter)}.</b> Like
 * {@link Identity} / {@link IdentityEmail}, this is a cross-tenant / platform-level
 * table by definition: it links a platform identity to a tenant. Tenant isolation
 * (the P0-1 hardening) is preserved at the MEMBERSHIP ({@code users}) layer and by
 * the consent GRANT itself (a tenant can only act on a person who explicitly opted
 * in). Filtering this table by tenant would break the identity-authority model and
 * is a misapplication of the P0-1 ratchet. See the {@link Identity} Javadoc and the
 * design doc's "Cross-cutting rules".
 */
@Entity
@Table(name = "identity_tenant_biometric_consent",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_identity_tenant_biometric_consent",
                columnNames = {"identity_id", "tenant_id", "method"}))
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // For JPA
@AllArgsConstructor(access = AccessLevel.PRIVATE)  // For Builder
@Builder
public class IdentityTenantBiometricConsent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** The platform identity (person) granting / revoking consent. */
    @Column(name = "identity_id", nullable = false)
    private UUID identityId;

    /** The tenant the consent applies to. */
    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    /**
     * NULL = consent applies to ALL biometric methods; a value (e.g.
     * {@code "FACE"}) scopes consent to that one method. Stored as the
     * {@code AuthMethodType} name.
     */
    @Column(name = "method")
    private String method;

    @Column(name = "granted", nullable = false)
    @Builder.Default
    private boolean granted = true;

    @Column(name = "granted_at")
    private Instant grantedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /**
     * Applies a grant/revoke decision, stamping the matching timestamp. Keeps the
     * mutation logic on the aggregate (the service only ever calls this).
     */
    public void apply(boolean grant) {
        this.granted = grant;
        Instant now = Instant.now();
        if (grant) {
            this.grantedAt = now;
            this.revokedAt = null;
        } else {
            this.revokedAt = now;
        }
    }

    /**
     * JPA-safe equality by immutable id (mirrors {@link Identity#equals(Object)}).
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IdentityTenantBiometricConsent other)) return false;
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return IdentityTenantBiometricConsent.class.hashCode();
    }
}
