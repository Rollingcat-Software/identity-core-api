package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.CreateAuthFlowCommand;
import com.fivucsas.identity.application.dto.command.UpdateAuthFlowCommand;
import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.port.input.ManageAuthFlowUseCase;
import com.fivucsas.identity.domain.model.auth.OperationType;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/auth-flows")
@RequiredArgsConstructor
public class AuthFlowController {

    private final ManageAuthFlowUseCase manageAuthFlowUseCase;

    @GetMapping
    @PreAuthorize("@rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<List<AuthFlowResponse>> getFlows(
            @PathVariable UUID tenantId,
            @RequestParam(required = false) OperationType operationType) {
        return ResponseEntity.ok(manageAuthFlowUseCase.listFlows(tenantId, operationType));
    }

    @GetMapping("/{flowId}")
    @PreAuthorize("@rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<AuthFlowResponse> getFlow(
            @PathVariable UUID tenantId,
            @PathVariable UUID flowId) {
        return ResponseEntity.ok(manageAuthFlowUseCase.getFlow(tenantId, flowId));
    }

    @PostMapping
    @PreAuthorize("@rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<AuthFlowResponse> createFlow(
            @PathVariable UUID tenantId,
            @Valid @RequestBody CreateAuthFlowCommand command) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(manageAuthFlowUseCase.createFlow(tenantId, command));
    }

    @PutMapping("/{flowId}")
    @PreAuthorize("@rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<AuthFlowResponse> updateFlow(
            @PathVariable UUID tenantId,
            @PathVariable UUID flowId,
            @Valid @RequestBody UpdateAuthFlowCommand command) {
        return ResponseEntity.ok(manageAuthFlowUseCase.updateFlow(tenantId, flowId, command));
    }

    @DeleteMapping("/{flowId}")
    @PreAuthorize("@rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<Void> deleteFlow(
            @PathVariable UUID tenantId,
            @PathVariable UUID flowId) {
        manageAuthFlowUseCase.deleteFlow(tenantId, flowId);
        return ResponseEntity.noContent().build();
    }
}
