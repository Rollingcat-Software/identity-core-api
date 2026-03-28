package com.fivucsas.identity.infrastructure.persistence.mapper;

import com.fivucsas.identity.domain.model.permission.Permission;
import com.fivucsas.identity.domain.model.role.Role;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Maps between domain Role and JPA Role entity.
 * Static utility class - no state, no Spring dependency.
 */
public final class RoleMapper {

    private RoleMapper() {}

    /**
     * Converts JPA entity to domain model (with permissions).
     */
    public static Role toDomain(com.fivucsas.identity.entity.Role jpa) {
        if (jpa == null) return null;

        Set<Permission> domainPermissions = PermissionMapper.toDomainSet(jpa.getPermissions());

        return Role.reconstitute(
            jpa.getId(),
            jpa.getTenant() != null ? jpa.getTenant().getId() : null,
            jpa.getName(),
            jpa.getDescription(),
            jpa.isSystemRole(),
            jpa.isActive(),
            domainPermissions,
            jpa.getCreatedAt(),
            jpa.getUpdatedAt(),
            jpa.getDeletedAt()
        );
    }

    /**
     * Converts domain model to JPA entity.
     * Note: Does NOT set the tenant relationship - caller must set it separately.
     * Does NOT set permissions - they are managed via the JoinTable.
     */
    public static com.fivucsas.identity.entity.Role toJpaEntity(Role domain) {
        if (domain == null) return null;

        return com.fivucsas.identity.entity.Role.builder()
            .id(domain.getId())
            .name(domain.getName())
            .description(domain.getDescription())
            .isSystemRole(domain.isSystemRole())
            .active(domain.isActive())
            .permissions(PermissionMapper.toJpaEntitySet(domain.getPermissions()))
            .createdAt(domain.getCreatedAt())
            .updatedAt(domain.getUpdatedAt())
            .deletedAt(domain.getDeletedAt())
            .build();
    }

    /**
     * Converts a collection of JPA entities to domain models.
     */
    public static List<Role> toDomainList(Collection<com.fivucsas.identity.entity.Role> jpaEntities) {
        if (jpaEntities == null) return List.of();
        return jpaEntities.stream()
            .map(RoleMapper::toDomain)
            .collect(Collectors.toList());
    }

    /**
     * Converts a collection of JPA entities to domain model set.
     */
    public static Set<Role> toDomainSet(Collection<com.fivucsas.identity.entity.Role> jpaEntities) {
        if (jpaEntities == null) return Set.of();
        return jpaEntities.stream()
            .map(RoleMapper::toDomain)
            .collect(Collectors.toSet());
    }
}
