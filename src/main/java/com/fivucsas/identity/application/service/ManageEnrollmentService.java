package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class ManageEnrollmentService implements ManageEnrollmentUseCase {

    private static final Set<AuthMethodType> BIOMETRIC_TYPES = Set.of(
            AuthMethodType.FACE, AuthMethodType.FINGERPRINT, AuthMethodType.VOICE);

    // All enrollment types auto-complete — the frontend only calls startEnrollment
    // AFTER the biometric service confirms success (face enrolled, voice enrolled, etc.)

    private final UserEnrollmentRepositoryPort userEnrollmentRepository;
    private final UserRepository userRepository;
    private final JpaTenantRepository tenantRepository;
    private final BiometricServicePort biometricServicePort;

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

        enrollment.completeEnrollment("{}");
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

        // Delete biometric data from external service when revoking biometric enrollments
        if (BIOMETRIC_TYPES.contains(methodType)) {
            deleteBiometricData(userId, methodType);
        }

        enrollment.revoke();
        userEnrollmentRepository.save(enrollment);
    }

    private void deleteBiometricData(UUID userId, AuthMethodType methodType) {
        try {
            switch (methodType) {
                case FACE -> biometricServicePort.deleteFace(userId);
                case FINGERPRINT -> biometricServicePort.deleteFingerprint(userId);
                case VOICE -> biometricServicePort.deleteVoice(userId);
                default -> { /* no-op for non-biometric types */ }
            }
            log.info("Biometric data deleted from external service for user: {} method: {}", userId, methodType);
        } catch (Exception e) {
            log.warn("Failed to delete biometric data from external service for user: {} method: {}. " +
                     "Enrollment revocation will proceed. Error: {}", userId, methodType, e.getMessage());
        }
    }
}
