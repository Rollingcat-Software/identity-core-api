package com.fivucsas.identity.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

/**
 * Composite primary key for {@link TenantEmailDomain}.
 *
 * <p>Combines {@code tenant_id} and {@code email_domain}. Email domain is
 * always lowercase; callers should not attempt to store mixed-case values —
 * the DB has a CHECK constraint enforcing this (see V44 migration).</p>
 */
@Embeddable
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TenantEmailDomainId implements Serializable {

    private static final long serialVersionUID = 1L;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "email_domain", nullable = false, length = 253)
    private String emailDomain;

    /**
     * Factory — lowercases the domain defensively so the caller cannot
     * accidentally insert a mixed-case row that violates the DB CHECK.
     */
    public static TenantEmailDomainId of(UUID tenantId, String emailDomain) {
        return new TenantEmailDomainId(
            tenantId,
            emailDomain == null ? null : emailDomain.toLowerCase().trim()
        );
    }
}
