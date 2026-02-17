package com.fivucsas.identity.repository;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.entity.UserEnrollment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserEnrollmentRepository extends JpaRepository<UserEnrollment, UUID> {
    List<UserEnrollment> findAllByUserId(UUID userId);
    Optional<UserEnrollment> findByUserIdAndAuthMethodType(UUID userId, AuthMethodType methodType);
    List<UserEnrollment> findAllByUserIdAndStatus(UUID userId, EnrollmentStatus status);
    List<UserEnrollment> findAllByTenantId(UUID tenantId);
}
