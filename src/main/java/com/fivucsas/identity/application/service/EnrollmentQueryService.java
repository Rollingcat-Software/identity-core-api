package com.fivucsas.identity.application.service;

import com.fivucsas.identity.dto.EnrollmentDto;
import com.fivucsas.identity.entity.BiometricData;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.exception.ResourceNotFoundException;
import com.fivucsas.identity.domain.repository.BiometricDataRepository;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Application service for enrollment query operations.
 *
 * Uses UserEnrollmentRepository as the primary source for enrollment data,
 * falling back to BiometricDataRepository for legacy records.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class EnrollmentQueryService {

    private final BiometricDataRepository biometricDataRepository;
    private final UserEnrollmentRepositoryPort userEnrollmentRepository;

    public List<EnrollmentDto> getAllEnrollments() {
        List<EnrollmentDto> enrollments = userEnrollmentRepository.findAll().stream()
                .map(this::mapEnrollmentToDto)
                .toList();
        if (!enrollments.isEmpty()) {
            return enrollments;
        }
        // Fall back to legacy BiometricData if no UserEnrollment records exist
        return biometricDataRepository.findAll().stream()
                .map(this::mapBiometricToDto)
                .toList();
    }

    public EnrollmentDto getEnrollmentById(UUID id) {
        return userEnrollmentRepository.findById(id)
                .map(this::mapEnrollmentToDto)
                .orElseGet(() -> {
                    BiometricData data = biometricDataRepository.findById(id)
                            .orElseThrow(() -> new ResourceNotFoundException("Enrollment not found: " + id));
                    return mapBiometricToDto(data);
                });
    }

    @Transactional
    public void deleteEnrollment(UUID id) {
        if (userEnrollmentRepository.existsById(id)) {
            userEnrollmentRepository.deleteById(id);
            log.info("UserEnrollment deleted: {}", id);
            return;
        }

        BiometricData data = biometricDataRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Enrollment not found: " + id));

        User user = data.getUser();
        if (user != null) {
            user.unenrollBiometric();
        }
        biometricDataRepository.deleteRecord(data);
        log.info("BiometricData enrollment deleted: {}", id);
    }

    private EnrollmentDto mapEnrollmentToDto(UserEnrollment enrollment) {
        return EnrollmentDto.builder()
                .id(enrollment.getId().toString())
                .userId(enrollment.getUser() != null ? enrollment.getUser().getId().toString() : null)
                .userName(enrollment.getUser() != null ? enrollment.getUser().getFullName() : null)
                .userEmail(enrollment.getUser() != null ? enrollment.getUser().getEmail() : null)
                .tenantId(enrollment.getTenant() != null ? enrollment.getTenant().getId().toString() : null)
                .authMethodType(enrollment.getAuthMethodType() != null ? enrollment.getAuthMethodType().name() : null)
                .status(enrollment.getStatus().name())
                .enrolledAt(enrollment.getEnrolledAt())
                .createdAt(enrollment.getCreatedAt())
                .updatedAt(enrollment.getUpdatedAt())
                .completedAt(enrollment.isEnrolled() ? enrollment.getEnrolledAt() : null)
                .build();
    }

    private EnrollmentDto mapBiometricToDto(BiometricData data) {
        User user = data.getUser();
        return EnrollmentDto.builder()
                .id(data.getId().toString())
                .userId(user != null ? user.getId().toString() : null)
                .userName(user != null ? user.getFullName() : null)
                .userEmail(user != null ? user.getEmail() : null)
                .tenantId(user != null && user.getTenant() != null ? user.getTenant().getId().toString() : null)
                .status(user != null && user.isBiometricEnrolled() ? "ENROLLED" : "PENDING")
                .enrolledAt(data.getEnrolledAt())
                .createdAt(data.getEnrolledAt())
                .completedAt(user != null && user.isBiometricEnrolled() ? data.getEnrolledAt() : null)
                .build();
    }
}
