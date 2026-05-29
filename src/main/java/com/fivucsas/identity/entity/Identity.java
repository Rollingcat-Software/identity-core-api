package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Platform-level PERSON / IDENTITY entity (Model A, Phase 1).
 *
 * <p>Introduced by V65. Extracts the PERSON concern out of the {@code users}
 * row, which historically fused person + auth-identity + tenant-membership. A
 * {@code users} row is now a tenant MEMBERSHIP that references one identity
 * (see {@link User#getIdentity()}); a single person may hold memberships in
 * several tenants (Phase 2 account-linking).
 *
 * <p><b>NOT TENANT-SCOPED — DO NOT ADD {@code @Filter(tenantFilter)}.</b>
 * Identities are cross-tenant / platform-level BY DESIGN. They carry no
 * tenant_id. Tenant isolation (the P0-1 hardening) is preserved at the
 * MEMBERSHIP ({@code users}) and CONSENT layers, never by hiding the identity.
 * Adding the tenant filter here would break account-linking and is a
 * misapplication of the P0-1 ratchet. See
 * {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md} ("Cross-cutting rules").
 */
@Entity
@Table(name = "identities")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // For JPA
@AllArgsConstructor(access = AccessLevel.PRIVATE) // For Builder
@Builder
public class Identity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * JPA-safe equality by immutable id (P2.10). See {@link User#equals(Object)}
     * for the full rationale (Hibernate-proxy compatibility + transient→persistent
     * hash stability).
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Identity other)) return false;
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return Identity.class.hashCode();
    }

    @Column(name = "display_name")
    private String displayName;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE";

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;
}
