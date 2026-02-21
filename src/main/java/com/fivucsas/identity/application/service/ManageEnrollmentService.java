package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ManageEnrollmentService implements ManageEnrollmentUseCase {

    private final UserEnrollmentRepository userEnrollmentRepository;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;

    @Override
    public List<EnrollmentResponse> getUserEnrollments(UUID userId) {
        return userEnrollmentRepository.findAllByUserId(userId).stream()
                .map(EnrollmentResponse::from)
                .toList();
    }

    @Override
    @Transactional
    public EnrollmentResponse startEnrollment(UUID userId, UUID tenantId, AuthMethodType methodType) {
        UserEnrollment enrollment = userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .orElseGet(() -> {
                    User user = userRepository.findById(userId)
                            .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
                    Tenant tenant = tenantRepository.findById(tenantId)
                            .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));
                    return UserEnrollment.builder()
                            .user(user)
                            .tenant(tenant)
                            .authMethodType(methodType)
                            .build();
                });

        enrollment.startEnrollment();
        return EnrollmentResponse.from(userEnrollmentRepository.save(enrollment));
    }

    @Override
    @Transactional
    public EnrollmentResponse completeEnrollment(UUID userId, AuthMethodType methodType, String enrollmentData) {
        UserEnrollment enrollment = userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .orElseThrow(() -> new EntityNotFoundException("Enrollment not found for user: " + userId + " method: " + methodType));

        enrollment.completeEnrollment(enrollmentData);
        return EnrollmentResponse.from(userEnrollmentRepository.save(enrollment));
    }

    @Override
    @Transactional
    public void revokeEnrollment(UUID userId, AuthMethodType methodType) {
        UserEnrollment enrollment = userEnrollmentRepository
                .findByUserIdAndAuthMethodType(userId, methodType)
                .orElseThrow(() -> new EntityNotFoundException("Enrollment not found for user: " + userId + " method: " + methodType));

        enrollment.revoke();
        userEnrollmentRepository.save(enrollment);
    }
}
