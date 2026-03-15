package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class UserRoleRepositoryAdapter implements UserRoleRepositoryPort {

    private final UserRoleRepository jpaRepository;

    @Override
    public UserRole save(UserRole userRole) {
        return jpaRepository.save(userRole);
    }

    @Override
    public void saveAll(List<UserRole> userRoles) {
        jpaRepository.saveAll(userRoles);
    }

    @Override
    public List<UserRole> findByIdUserId(UUID userId) {
        return jpaRepository.findByIdUserId(userId);
    }

    @Override
    public List<UserRole> findByUserIdWithRole(UUID userId) {
        return jpaRepository.findByUserIdWithRole(userId);
    }

    @Override
    public List<UserRole> findByRoleIdWithUser(UUID roleId) {
        return jpaRepository.findByRoleIdWithUser(roleId);
    }

    @Override
    public boolean existsByIdUserIdAndIdRoleId(UUID userId, UUID roleId) {
        return jpaRepository.existsByIdUserIdAndIdRoleId(userId, roleId);
    }

    @Override
    public void deleteByUserIdAndRoleId(UUID userId, UUID roleId) {
        jpaRepository.deleteByUserIdAndRoleId(userId, roleId);
    }

    @Override
    public void deleteAllByUserId(UUID userId) {
        jpaRepository.deleteAllByUserId(userId);
    }

    @Override
    public int deleteExpiredAssignments(Instant now) {
        return jpaRepository.deleteExpiredAssignments(now);
    }
}
