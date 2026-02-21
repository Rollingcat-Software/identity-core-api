package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users/{userId}/enrollments")
@RequiredArgsConstructor
public class EnrollmentManagementController {

    private final ManageEnrollmentUseCase manageEnrollmentUseCase;

    @GetMapping
    @PreAuthorize("hasPermission(#userId, 'User', 'enrollment:read')")
    public ResponseEntity<List<EnrollmentResponse>> getUserEnrollments(@PathVariable UUID userId) {
        return ResponseEntity.ok(manageEnrollmentUseCase.getUserEnrollments(userId));
    }

    @PostMapping
    @PreAuthorize("hasPermission(#userId, 'User', 'enrollment:create')")
    public ResponseEntity<EnrollmentResponse> startEnrollment(
            @PathVariable UUID userId,
            @RequestParam UUID tenantId,
            @RequestParam AuthMethodType methodType) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(manageEnrollmentUseCase.startEnrollment(userId, tenantId, methodType));
    }

    @DeleteMapping("/{methodType}")
    @PreAuthorize("hasPermission(#userId, 'User', 'enrollment:delete')")
    public ResponseEntity<Void> revokeEnrollment(
            @PathVariable UUID userId,
            @PathVariable AuthMethodType methodType) {
        manageEnrollmentUseCase.revokeEnrollment(userId, methodType);
        return ResponseEntity.noContent().build();
    }
}
