package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.domain.model.permission.Permission;
import com.fivucsas.identity.domain.repository.PermissionDomainRepository;
import com.fivucsas.identity.infrastructure.persistence.mapper.PermissionMapper;
import com.fivucsas.identity.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Infrastructure adapter bridging the pure domain PermissionDomainRepository port
 * to the Spring Data JPA repository.
 *
 * Converts between domain Permission models and JPA Permission entities using PermissionMapper.
 * This adapter returns domain models only -- no JPA entity leakage.
 *
 * For backward compatibility, the existing PermissionRepositoryAdapter (returning JPA entities)
 * remains available for services not yet migrated to domain models.
 */
@Repository
@RequiredArgsConstructor
public class PermissionDomainRepositoryAdapter implements PermissionDomainRepository {

    private final PermissionRepository jpaRepository;

    @Override
    public Optional<Permission> findById(UUID id) {
        return jpaRepository.findById(id).map(PermissionMapper::toDomain);
    }

    @Override
    public List<Permission> findAllOrdered() {
        return jpaRepository.findAllOrdered().stream()
            .map(PermissionMapper::toDomain)
            .toList();
    }

    @Override
    public List<Permission> findByResource(String resource) {
        return jpaRepository.findByResource(resource).stream()
            .map(PermissionMapper::toDomain)
            .toList();
    }

    @Override
    public List<Permission> findByIdIn(List<UUID> ids) {
        return jpaRepository.findByIdIn(ids).stream()
            .map(PermissionMapper::toDomain)
            .toList();
    }
}
