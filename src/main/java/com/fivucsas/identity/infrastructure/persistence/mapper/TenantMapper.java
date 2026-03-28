package com.fivucsas.identity.infrastructure.persistence.mapper;

import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.model.tenant.TenantConfiguration;
import com.fivucsas.identity.domain.model.tenant.TenantStatus;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Maps between domain Tenant and JPA Tenant entity.
 * Static utility class - no state, no Spring dependency.
 */
public final class TenantMapper {

    private TenantMapper() {}

    /**
     * Converts JPA entity to domain model.
     */
    public static Tenant toDomain(com.fivucsas.identity.entity.Tenant jpa) {
        if (jpa == null) return null;

        TenantStatus domainStatus = convertStatus(jpa.getStatus());
        TenantConfiguration config = TenantConfiguration.of(
            jpa.getMaxUsers(),
            jpa.isBiometricEnabled(),
            jpa.getSessionTimeoutMinutes(),
            jpa.getRefreshTokenValidityDays(),
            jpa.isMfaRequired()
        );

        return Tenant.reconstitute(
            jpa.getId(),
            jpa.getName(),
            jpa.getSlug(),
            jpa.getDescription(),
            jpa.getContactEmail(),
            jpa.getContactPhone(),
            domainStatus,
            config,
            jpa.getCreatedAt(),
            jpa.getUpdatedAt()
        );
    }

    /**
     * Converts domain model to JPA entity.
     */
    public static com.fivucsas.identity.entity.Tenant toJpaEntity(Tenant domain) {
        if (domain == null) return null;

        return com.fivucsas.identity.entity.Tenant.builder()
            .id(domain.getId())
            .name(domain.getName())
            .slug(domain.getSlug())
            .description(domain.getDescription())
            .contactEmail(domain.getContactEmail())
            .contactPhone(domain.getContactPhone())
            .status(convertStatus(domain.getStatus()))
            .maxUsers(domain.getMaxUsers())
            .biometricEnabled(domain.isBiometricEnabled())
            .sessionTimeoutMinutes(domain.getSessionTimeoutMinutes())
            .refreshTokenValidityDays(domain.getRefreshTokenValidityDays())
            .mfaRequired(domain.isMfaRequired())
            .createdAt(domain.getCreatedAt())
            .updatedAt(domain.getUpdatedAt())
            .build();
    }

    /**
     * Converts a collection of JPA entities to domain models.
     */
    public static List<Tenant> toDomainList(Collection<com.fivucsas.identity.entity.Tenant> jpaEntities) {
        if (jpaEntities == null) return List.of();
        return jpaEntities.stream()
            .map(TenantMapper::toDomain)
            .collect(Collectors.toList());
    }

    // ========== Status Conversion Helpers ==========

    private static TenantStatus convertStatus(com.fivucsas.identity.entity.TenantStatus jpaStatus) {
        if (jpaStatus == null) return TenantStatus.PENDING;
        return TenantStatus.valueOf(jpaStatus.name());
    }

    private static com.fivucsas.identity.entity.TenantStatus convertStatus(TenantStatus domainStatus) {
        if (domainStatus == null) return com.fivucsas.identity.entity.TenantStatus.PENDING;
        return com.fivucsas.identity.entity.TenantStatus.valueOf(domainStatus.name());
    }
}
