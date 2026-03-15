package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.PermissionRepositoryPort;
import com.fivucsas.identity.entity.Permission;
import com.fivucsas.identity.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class PermissionRepositoryAdapter implements PermissionRepositoryPort {

    private final PermissionRepository jpaRepository;

    @Override
    public Optional<Permission> findById(UUID id) {
        return jpaRepository.findById(id);
    }

    @Override
    public List<Permission> findAllOrdered() {
        return jpaRepository.findAllOrdered();
    }

    @Override
    public List<Permission> findByResource(String resource) {
        return jpaRepository.findByResource(resource);
    }

    @Override
    public List<Permission> findByIdIn(List<UUID> ids) {
        return jpaRepository.findByIdIn(ids);
    }
}
