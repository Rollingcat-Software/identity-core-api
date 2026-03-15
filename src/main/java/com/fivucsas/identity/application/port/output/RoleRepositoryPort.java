package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.Permission;
import com.fivucsas.identity.entity.Role;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for Role persistence operations.
 */
public interface RoleRepositoryPort {

    Optional<Role> findById(UUID id);

    Optional<Role> findByIdWithPermissions(UUID id);

    Optional<Role> findByNameAndDeletedAtIsNull(String name);

    Optional<Role> findByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name);

    boolean existsByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name);

    List<Role> findAllWithPermissions();

    List<Role> findAllActiveWithPermissions();

    List<Role> findByTenantIdWithPermissions(UUID tenantId);

    Role save(Role role);
}
