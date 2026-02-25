package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.service.EnrollmentQueryService;
import com.fivucsas.identity.dto.EnrollmentDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/enrollments")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Enrollments", description = "Biometric enrollment management")
public class EnrollmentController {

    private final EnrollmentQueryService enrollmentQueryService;

    @GetMapping
    @Operation(summary = "Get all enrollments")
    @PreAuthorize("hasPermission(null, 'enrollment', 'read')")
    public ResponseEntity<List<EnrollmentDto>> getAllEnrollments() {
        log.info("GET /api/v1/enrollments");
        return ResponseEntity.ok(enrollmentQueryService.getAllEnrollments());
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get enrollment by ID")
    @PreAuthorize("hasPermission(null, 'enrollment', 'read')")
    public ResponseEntity<EnrollmentDto> getEnrollmentById(@PathVariable String id) {
        log.info("GET /api/v1/enrollments/{}", id);
        return ResponseEntity.ok(enrollmentQueryService.getEnrollmentById(UUID.fromString(id)));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete an enrollment")
    @PreAuthorize("hasPermission(null, 'enrollment', 'delete')")
    public ResponseEntity<Void> deleteEnrollment(@PathVariable String id) {
        log.info("DELETE /api/v1/enrollments/{}", id);
        enrollmentQueryService.deleteEnrollment(UUID.fromString(id));
        return ResponseEntity.noContent().build();
    }
}
