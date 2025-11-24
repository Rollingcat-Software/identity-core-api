package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * JPA Repository for Role entity.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByTenantIdAndName(UUID tenantId, String name);

    List<Role> findByTenantId(UUID tenantId);

    boolean existsByTenantIdAndName(UUID tenantId, String name);

    List<Role> findByIsSystemRole(boolean isSystemRole);
}
