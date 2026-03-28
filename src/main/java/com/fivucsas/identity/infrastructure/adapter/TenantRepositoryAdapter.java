package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.model.tenant.TenantStatus;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.infrastructure.persistence.mapper.TenantMapper;
import com.fivucsas.identity.repository.JpaTenantRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Infrastructure adapter bridging the domain TenantRepository port
 * to the Spring Data JPA repository.
 *
 * Converts between domain Tenant models and JPA Tenant entities.
 * Follows Hexagonal Architecture: domain defines the port,
 * infrastructure provides the implementation with mapping.
 */
@Repository
@RequiredArgsConstructor
public class TenantRepositoryAdapter implements TenantRepository {

    private final JpaTenantRepository jpaRepository;

    @Override
    public Tenant save(Tenant domain) {
        com.fivucsas.identity.entity.Tenant jpaEntity = TenantMapper.toJpaEntity(domain);
        com.fivucsas.identity.entity.Tenant saved = jpaRepository.save(jpaEntity);
        return TenantMapper.toDomain(saved);
    }

    @Override
    public Optional<Tenant> findById(UUID id) {
        return jpaRepository.findById(id).map(TenantMapper::toDomain);
    }

    @Override
    public Optional<Tenant> findBySlug(String slug) {
        return jpaRepository.findBySlug(slug).map(TenantMapper::toDomain);
    }

    @Override
    public Optional<Tenant> findByName(String name) {
        return jpaRepository.findByName(name).map(TenantMapper::toDomain);
    }

    @Override
    public List<Tenant> findAll() {
        return TenantMapper.toDomainList(jpaRepository.findAll());
    }

    @Override
    public List<Tenant> findByStatus(TenantStatus status) {
        com.fivucsas.identity.entity.TenantStatus jpaStatus =
            com.fivucsas.identity.entity.TenantStatus.valueOf(status.name());
        return TenantMapper.toDomainList(jpaRepository.findByStatus(jpaStatus));
    }

    @Override
    public boolean existsBySlug(String slug) {
        return jpaRepository.existsBySlug(slug);
    }

    @Override
    public boolean existsByName(String name) {
        return jpaRepository.existsByName(name);
    }

    @Override
    public void deleteById(UUID id) {
        jpaRepository.deleteById(id);
    }

    @Override
    public long count() {
        return jpaRepository.count();
    }

    @Override
    public long countByStatus(TenantStatus status) {
        com.fivucsas.identity.entity.TenantStatus jpaStatus =
            com.fivucsas.identity.entity.TenantStatus.valueOf(status.name());
        return jpaRepository.countByStatus(jpaStatus);
    }
}
