package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA Repository for Tenant entity.
 * Pure infrastructure concern - no domain interfaces.
 * The TenantRepositoryAdapter bridges this to the domain layer.
 */
@Repository
public interface JpaTenantRepository extends JpaRepository<Tenant, UUID> {

    Optional<Tenant> findBySlug(String slug);

    Optional<Tenant> findByName(String name);

    List<Tenant> findByStatus(TenantStatus status);

    boolean existsBySlug(String slug);

    boolean existsByName(String name);

    long countByStatus(TenantStatus status);
}
