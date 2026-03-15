package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class RoleRepositoryAdapter implements RoleRepositoryPort {

    private final RoleRepository jpaRepository;

    @Override
    public Optional<Role> findById(UUID id) {
        return jpaRepository.findById(id);
    }

    @Override
    public Optional<Role> findByIdWithPermissions(UUID id) {
        return jpaRepository.findByIdWithPermissions(id);
    }

    @Override
    public Optional<Role> findByNameAndDeletedAtIsNull(String name) {
        return jpaRepository.findByNameAndDeletedAtIsNull(name);
    }

    @Override
    public Optional<Role> findByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name) {
        return jpaRepository.findByTenantIdAndNameAndDeletedAtIsNull(tenantId, name);
    }

    @Override
    public boolean existsByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name) {
        return jpaRepository.existsByTenantIdAndNameAndDeletedAtIsNull(tenantId, name);
    }

    @Override
    public List<Role> findAllWithPermissions() {
        return jpaRepository.findAllWithPermissions();
    }

    @Override
    public List<Role> findAllActiveWithPermissions() {
        return jpaRepository.findAllActiveWithPermissions();
    }

    @Override
    public List<Role> findByTenantIdWithPermissions(UUID tenantId) {
        return jpaRepository.findByTenantIdWithPermissions(tenantId);
    }

    @Override
    public Role save(Role role) {
        return jpaRepository.save(role);
    }
}
