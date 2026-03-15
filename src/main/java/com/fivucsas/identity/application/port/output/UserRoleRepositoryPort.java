package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.entity.UserRoleId;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Output port for UserRole persistence operations.
 */
public interface UserRoleRepositoryPort {

    UserRole save(UserRole userRole);

    void saveAll(List<UserRole> userRoles);

    List<UserRole> findByIdUserId(UUID userId);

    List<UserRole> findByUserIdWithRole(UUID userId);

    List<UserRole> findByRoleIdWithUser(UUID roleId);

    boolean existsByIdUserIdAndIdRoleId(UUID userId, UUID roleId);

    void deleteByUserIdAndRoleId(UUID userId, UUID roleId);

    void deleteAllByUserId(UUID userId);

    int deleteExpiredAssignments(Instant now);
}
