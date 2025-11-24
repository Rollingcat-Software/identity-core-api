package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * JPA Repository for Tenant entity.
 *
 * Extends both:
 * - JpaRepository: Provides JPA/Spring Data features
 * - TenantRepository (domain): Implements domain repository contract
 *
 * Following Dependency Inversion Principle:
 * - Infrastructure (this) implements domain interface
 * - Services depend on domain interface, not this
 */
@Repository
public interface JpaTenantRepository extends
        JpaRepository<Tenant, UUID>,
        com.fivucsas.identity.domain.repository.TenantRepository {

    Optional<Tenant> findBySlug(String slug);

    Optional<Tenant> findByName(String name);

    List<Tenant> findByStatus(TenantStatus status);

    boolean existsBySlug(String slug);

    boolean existsByName(String name);

    long countByStatus(TenantStatus status);
}
