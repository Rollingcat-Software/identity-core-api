package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.Permission;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for Permission persistence operations.
 */
public interface PermissionRepositoryPort {

    Optional<Permission> findById(UUID id);

    List<Permission> findAllOrdered();

    List<Permission> findByResource(String resource);

    List<Permission> findByIdIn(List<UUID> ids);
}
