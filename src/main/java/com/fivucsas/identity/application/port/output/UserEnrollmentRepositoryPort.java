package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.UserEnrollment;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for UserEnrollment persistence operations.
 */
public interface UserEnrollmentRepositoryPort {

    List<UserEnrollment> findAll();

    /**
     * Returns all enrollments for a given tenant. Used for tenant-scoped
     * listings so TENANT_ADMIN callers never see other tenants' data.
     */
    List<UserEnrollment> findAllByTenantId(UUID tenantId);

    List<UserEnrollment> findAllByUserId(UUID userId);

    Optional<UserEnrollment> findById(UUID id);

    Optional<UserEnrollment> findByUserIdAndAuthMethodType(UUID userId, AuthMethodType methodType);

    boolean existsById(UUID id);

    void deleteById(UUID id);

    UserEnrollment save(UserEnrollment enrollment);
}
