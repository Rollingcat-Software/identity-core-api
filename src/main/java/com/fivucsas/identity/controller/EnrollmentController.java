package com.fivucsas.identity.controller;

import com.fivucsas.identity.dto.EnrollmentDto;
import com.fivucsas.identity.entity.BiometricData;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.exception.ResourceNotFoundException;
import com.fivucsas.identity.repository.BiometricDataRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/enrollments")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Enrollments", description = "Biometric enrollment management")
public class EnrollmentController {

    private final BiometricDataRepository biometricDataRepository;

    @GetMapping
    @Operation(summary = "Get all enrollments")
    public ResponseEntity<List<EnrollmentDto>> getAllEnrollments() {
        log.info("GET /api/v1/enrollments");

        List<EnrollmentDto> enrollments = biometricDataRepository.findAll().stream()
                .map(this::mapToDto)
                .toList();

        return ResponseEntity.ok(enrollments);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get enrollment by ID")
    public ResponseEntity<EnrollmentDto> getEnrollmentById(@PathVariable String id) {
        log.info("GET /api/v1/enrollments/{}", id);

        BiometricData data = biometricDataRepository.findById(UUID.fromString(id))
                .orElseThrow(() -> new ResourceNotFoundException("Enrollment not found: " + id));

        return ResponseEntity.ok(mapToDto(data));
    }

    @PostMapping("/{id}/retry")
    @Operation(summary = "Retry a failed enrollment")
    public ResponseEntity<EnrollmentDto> retryEnrollment(@PathVariable String id) {
        log.info("POST /api/v1/enrollments/{}/retry", id);

        BiometricData data = biometricDataRepository.findById(UUID.fromString(id))
                .orElseThrow(() -> new ResourceNotFoundException("Enrollment not found: " + id));

        return ResponseEntity.ok(mapToDto(data));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete an enrollment")
    public ResponseEntity<Void> deleteEnrollment(@PathVariable String id) {
        log.info("DELETE /api/v1/enrollments/{}", id);

        BiometricData data = biometricDataRepository.findById(UUID.fromString(id))
                .orElseThrow(() -> new ResourceNotFoundException("Enrollment not found: " + id));

        User user = data.getUser();
        user.unenrollBiometric();
        biometricDataRepository.delete(data);

        return ResponseEntity.noContent().build();
    }

    private EnrollmentDto mapToDto(BiometricData data) {
        User user = data.getUser();
        return EnrollmentDto.builder()
                .id(data.getId().toString())
                .userId(user != null ? user.getId().toString() : null)
                .userName(user != null ? user.getFullName() : null)
                .userEmail(user != null ? user.getEmail() : null)
                .status("COMPLETED")
                .enrolledAt(data.getEnrolledAt())
                .build();
    }
}
