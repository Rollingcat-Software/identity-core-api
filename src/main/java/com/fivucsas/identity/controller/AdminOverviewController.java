package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.dto.response.AuthSessionResponse;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.repository.AuthFlowRepository;
import com.fivucsas.identity.repository.AuthSessionRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Admin-level overview endpoints for auth flows and auth sessions.
 *
 * These endpoints list all records across all tenants for the admin dashboard.
 * The tenant-scoped CRUD operations remain in AuthFlowController and AuthSessionController.
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin Overview", description = "Cross-tenant admin overview endpoints")
public class AdminOverviewController {

    private final AuthFlowRepository authFlowRepository;
    private final AuthSessionRepository authSessionRepository;

    @GetMapping("/auth-flows")
    @Operation(summary = "List all auth flows across all tenants (admin)")
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @Transactional(readOnly = true)
    public ResponseEntity<List<AuthFlowResponse>> getAllAuthFlows(
            @RequestParam(required = false) OperationType operationType) {
        log.info("GET /api/v1/auth-flows - List all auth flows");
        List<AuthFlowResponse> flows = authFlowRepository.findAll().stream()
                .filter(f -> operationType == null || f.getOperationType() == operationType)
                .map(AuthFlowResponse::from)
                .toList();
        return ResponseEntity.ok(flows);
    }

    @GetMapping("/auth-sessions")
    @Operation(summary = "List all auth sessions across all tenants (admin)")
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @Transactional(readOnly = true)
    public ResponseEntity<List<AuthSessionResponse>> getAllAuthSessions() {
        log.info("GET /api/v1/auth-sessions - List all auth sessions");
        List<AuthSessionResponse> sessions = authSessionRepository.findAll().stream()
                .map(AuthSessionResponse::from)
                .toList();
        return ResponseEntity.ok(sessions);
    }
}
