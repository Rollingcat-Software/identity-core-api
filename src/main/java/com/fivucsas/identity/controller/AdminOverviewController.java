package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.dto.response.AuthSessionResponse;
import com.fivucsas.identity.application.service.AdminOverviewService;
import com.fivucsas.identity.domain.model.auth.OperationType;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Admin-level overview endpoints for auth flows and auth sessions.
 *
 * These endpoints list all records across all tenants for the admin dashboard.
 * The tenant-scoped CRUD operations remain in AuthFlowController and AuthSessionController.
 *
 * <p>Transaction boundary lives in {@link AdminOverviewService}, not on the
 * controller methods (P1-Q9, quality review 2026-05-01).</p>
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin Overview", description = "Cross-tenant admin overview endpoints")
public class AdminOverviewController {

    private final AdminOverviewService adminOverviewService;

    @GetMapping("/auth-flows")
    @Operation(summary = "List all auth flows across all tenants (admin)")
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    public ResponseEntity<List<AuthFlowResponse>> getAllAuthFlows(
            @RequestParam(required = false) OperationType operationType) {
        log.info("GET /api/v1/auth-flows - List all auth flows");
        return ResponseEntity.ok(adminOverviewService.listAllAuthFlows(operationType));
    }

    @GetMapping("/auth-sessions")
    @Operation(summary = "List all auth sessions across all tenants (admin)")
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    public ResponseEntity<List<AuthSessionResponse>> getAllAuthSessions() {
        log.info("GET /api/v1/auth-sessions - List all auth sessions");
        return ResponseEntity.ok(adminOverviewService.listAllAuthSessions());
    }
}
