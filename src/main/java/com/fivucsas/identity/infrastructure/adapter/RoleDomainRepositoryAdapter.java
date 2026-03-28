package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.domain.model.role.Role;
import com.fivucsas.identity.domain.repository.RoleDomainRepository;
import com.fivucsas.identity.infrastructure.persistence.mapper.RoleMapper;
import com.fivucsas.identity.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Infrastructure adapter bridging the pure domain RoleDomainRepository port
 * to the Spring Data JPA repository.
 *
 * Converts between domain Role models and JPA Role entities using RoleMapper.
 * This adapter returns domain models only -- no JPA entity leakage.
 *
 * For backward compatibility, the existing RoleRepositoryAdapter (returning JPA entities)
 * remains available for services not yet migrated to domain models.
 */
@Repository
@RequiredArgsConstructor
public class RoleDomainRepositoryAdapter implements RoleDomainRepository {

    private final RoleRepository jpaRepository;

    @Override
    public Optional<Role> findById(UUID id) {
        return jpaRepository.findById(id).map(RoleMapper::toDomain);
    }

    @Override
    public Optional<Role> findByIdWithPermissions(UUID id) {
        return jpaRepository.findByIdWithPermissions(id).map(RoleMapper::toDomain);
    }

    @Override
    public Optional<Role> findByNameAndDeletedAtIsNull(String name) {
        return jpaRepository.findByNameAndDeletedAtIsNull(name).map(RoleMapper::toDomain);
    }

    @Override
    public Optional<Role> findByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name) {
        return jpaRepository.findByTenantIdAndNameAndDeletedAtIsNull(tenantId, name)
            .map(RoleMapper::toDomain);
    }

    @Override
    public boolean existsByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name) {
        return jpaRepository.existsByTenantIdAndNameAndDeletedAtIsNull(tenantId, name);
    }

    @Override
    public List<Role> findAllWithPermissions() {
        return RoleMapper.toDomainList(jpaRepository.findAllWithPermissions());
    }

    @Override
    public List<Role> findAllActiveWithPermissions() {
        return RoleMapper.toDomainList(jpaRepository.findAllActiveWithPermissions());
    }

    @Override
    public List<Role> findByTenantIdWithPermissions(UUID tenantId) {
        return RoleMapper.toDomainList(jpaRepository.findByTenantIdWithPermissions(tenantId));
    }

    @Override
    public Role save(Role domain) {
        com.fivucsas.identity.entity.Role jpaEntity = RoleMapper.toJpaEntity(domain);
        // Rebuild with tenant reference if tenantId is present.
        // Since JPA Role entity uses @Builder with private all-args constructor,
        // we reconstruct the entity with the tenant set via builder.
        if (domain.getTenantId() != null) {
            com.fivucsas.identity.entity.Tenant tenantRef =
                com.fivucsas.identity.entity.Tenant.builder()
                    .id(domain.getTenantId())
                    .build();
            jpaEntity = com.fivucsas.identity.entity.Role.builder()
                .id(jpaEntity.getId())
                .tenant(tenantRef)
                .name(jpaEntity.getName())
                .description(jpaEntity.getDescription())
                .isSystemRole(jpaEntity.isSystemRole())
                .active(jpaEntity.isActive())
                .permissions(jpaEntity.getPermissions())
                .createdAt(jpaEntity.getCreatedAt())
                .updatedAt(jpaEntity.getUpdatedAt())
                .deletedAt(jpaEntity.getDeletedAt())
                .build();
        }
        com.fivucsas.identity.entity.Role saved = jpaRepository.save(jpaEntity);
        return RoleMapper.toDomain(saved);
    }
}
