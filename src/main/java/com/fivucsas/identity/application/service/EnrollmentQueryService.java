package com.fivucsas.identity.application.service;

import com.fivucsas.identity.dto.EnrollmentDto;
import com.fivucsas.identity.entity.BiometricData;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.exception.ResourceNotFoundException;
import com.fivucsas.identity.repository.BiometricDataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Application service for enrollment query operations.
 *
 * Wraps BiometricDataRepository access behind the application layer,
 * keeping the controller (adapter) free of direct infrastructure dependencies.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class EnrollmentQueryService {

    private final BiometricDataRepository biometricDataRepository;

    public List<EnrollmentDto> getAllEnrollments() {
        return biometricDataRepository.findAll().stream()
                .map(this::mapToDto)
                .toList();
    }

    public EnrollmentDto getEnrollmentById(UUID id) {
        BiometricData data = biometricDataRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Enrollment not found: " + id));
        return mapToDto(data);
    }

    @Transactional
    public void deleteEnrollment(UUID id) {
        BiometricData data = biometricDataRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Enrollment not found: " + id));

        User user = data.getUser();
        if (user != null) {
            user.unenrollBiometric();
        }
        biometricDataRepository.delete(data);
        log.info("Enrollment deleted: {}", id);
    }

    private EnrollmentDto mapToDto(BiometricData data) {
        User user = data.getUser();
        return EnrollmentDto.builder()
                .id(data.getId().toString())
                .userId(user != null ? user.getId().toString() : null)
                .userName(user != null ? user.getFullName() : null)
                .userEmail(user != null ? user.getEmail() : null)
                .tenantId(user != null && user.getTenant() != null ? user.getTenant().getId().toString() : null)
                .status(user != null && user.isBiometricEnrolled() ? "COMPLETED" : "PENDING")
                .enrolledAt(data.getEnrolledAt())
                .createdAt(data.getEnrolledAt())
                .completedAt(user != null && user.isBiometricEnrolled() ? data.getEnrolledAt() : null)
                .build();
    }
}
