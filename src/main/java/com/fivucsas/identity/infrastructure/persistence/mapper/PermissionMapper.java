package com.fivucsas.identity.infrastructure.persistence.mapper;

import com.fivucsas.identity.domain.model.permission.Permission;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Maps between domain Permission and JPA Permission entity.
 * Static utility class - no state, no Spring dependency.
 */
public final class PermissionMapper {

    private PermissionMapper() {}

    /**
     * Converts JPA entity to domain model.
     */
    public static Permission toDomain(com.fivucsas.identity.entity.Permission jpa) {
        if (jpa == null) return null;
        return Permission.reconstitute(
            jpa.getId(),
            jpa.getName(),
            jpa.getDescription(),
            jpa.getResource(),
            jpa.getAction()
        );
    }

    /**
     * Converts domain model to JPA entity.
     */
    public static com.fivucsas.identity.entity.Permission toJpaEntity(Permission domain) {
        if (domain == null) return null;
        return com.fivucsas.identity.entity.Permission.builder()
            .id(domain.getId())
            .name(domain.getName())
            .description(domain.getDescription())
            .resource(domain.getResource())
            .action(domain.getAction())
            .build();
    }

    /**
     * Converts a collection of JPA entities to domain models.
     */
    public static Set<Permission> toDomainSet(Collection<com.fivucsas.identity.entity.Permission> jpaEntities) {
        if (jpaEntities == null) return Set.of();
        return jpaEntities.stream()
            .map(PermissionMapper::toDomain)
            .collect(Collectors.toSet());
    }

    /**
     * Converts a collection of domain models to JPA entities.
     */
    public static Set<com.fivucsas.identity.entity.Permission> toJpaEntitySet(Collection<Permission> domains) {
        if (domains == null) return Set.of();
        return domains.stream()
            .map(PermissionMapper::toJpaEntity)
            .collect(Collectors.toSet());
    }
}
