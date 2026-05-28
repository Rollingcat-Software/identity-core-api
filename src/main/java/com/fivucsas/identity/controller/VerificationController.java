package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.CreateVerificationSessionCommand;
import com.fivucsas.identity.application.dto.command.ReviewVerificationStepCommand;
import com.fivucsas.identity.application.dto.command.SubmitVerificationStepCommand;
import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.dto.response.IndustryTemplateResponse;
import com.fivucsas.identity.application.dto.response.VerificationSessionResponse;
import com.fivucsas.identity.application.dto.response.VerificationStatusResponse;
import com.fivucsas.identity.application.dto.response.VerificationStepResultResponse;
import com.fivucsas.identity.application.service.ManageVerificationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/verification")
@RequiredArgsConstructor
public class VerificationController {

    private final ManageVerificationService verificationService;
    private final TenantScopeResolver tenantScopeResolver;

    /**
     * Creates a verification session ON BEHALF OF a tenant user (admin-on-behalf
     * model: the admin dashboard posts the target {@code userId}). S2 fix —
     * previously this endpoint had no {@code @PreAuthorize}, so any authenticated
     * caller could mint a session for ANY user in ANY tenant (write-side IDOR).
     *
     * <p>Defence is two-layered, mirroring the S1 fix on {@code TenantController}:
     * the {@code verification:create} permission gate here (ROOT and TENANT_ADMIN
     * hold it; see V45), plus an object-level tenant-scope + user-ownership check
     * inside {@link ManageVerificationService#createSession} so a TENANT_ADMIN of
     * tenant A cannot pass tenant B's id.</p>
     */
    @PostMapping("/sessions")
    @PreAuthorize("@rbac.hasPermission('verification:create')")
    public ResponseEntity<VerificationSessionResponse> createSession(
            @Valid @RequestBody CreateVerificationSessionCommand command) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(verificationService.createSession(command.userId(), command.tenantId(), command.flowId()));
    }

    @PostMapping("/sessions/{id}/steps/{stepNumber}")
    public ResponseEntity<VerificationStepResultResponse> submitStepResult(
            @PathVariable UUID id,
            @PathVariable int stepNumber,
            @Valid @RequestBody SubmitVerificationStepCommand command) {
        return ResponseEntity.ok(verificationService.submitStepResult(id, stepNumber, command));
    }

    /**
     * Reads a single verification session. S2 fix — object-level authz lives in
     * {@link ManageVerificationService#getSession}: the resolved session's tenant
     * must satisfy {@code tenantScopeResolver.canAccessTenant(...)} (ROOT/SUPER_ADMIN
     * unrestricted), else 403. Without it any authenticated caller could read any
     * other tenant's session by guessing the id (read-side IDOR).
     */
    @GetMapping("/sessions/{id}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<VerificationSessionResponse> getSession(@PathVariable UUID id) {
        return ResponseEntity.ok(verificationService.getSession(id));
    }

    /**
     * Completes a verification session (admin-on-behalf). S2 fix — object-level
     * tenant-scope check inside {@link ManageVerificationService#completeSession}
     * stops a caller from completing another tenant's session (write-side IDOR
     * that would also flip that user's {@code identityVerified} flag).
     */
    @PostMapping("/sessions/{id}/complete")
    @PreAuthorize("@rbac.hasPermission('verification:create')")
    public ResponseEntity<VerificationSessionResponse> completeSession(@PathVariable UUID id) {
        return ResponseEntity.ok(verificationService.completeSession(id));
    }

    @GetMapping("/templates")
    public ResponseEntity<List<IndustryTemplateResponse>> getTemplates() {
        return ResponseEntity.ok(verificationService.getTemplates());
    }

    /**
     * Lists VERIFICATION-type auth flows for a tenant. Tenant-scoped: a
     * TENANT_ADMIN may only query their own tenant; SUPER_ADMIN may query any.
     * Unknown/unauthorized tenantId → empty list (dashboard-friendly) rather
     * than 403 so the page renders.
     */
    @GetMapping("/flows")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<AuthFlowResponse>> listFlows(
            @RequestParam(required = false) UUID tenantId) {
        UUID callerScope = tenantScopeResolver.currentScope();
        UUID effectiveTenantId;
        if (callerScope == null) {
            // SUPER_ADMIN — honor query param. When omitted, the service
            // returns every VERIFICATION flow on the platform so the
            // dashboard renders real data instead of a fake empty state.
            effectiveTenantId = tenantId;
        } else if (TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE.equals(callerScope)) {
            return ResponseEntity.ok(List.of());
        } else {
            // Tenant-scoped caller: always pin to their own tenant.
            effectiveTenantId = callerScope;
        }
        return ResponseEntity.ok(verificationService.getVerificationFlows(effectiveTenantId));
    }

    /**
     * Aggregate verification stats. Same scoping rule as {@code /flows}.
     */
    @GetMapping("/stats")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> stats(
            @RequestParam(required = false) UUID tenantId) {
        UUID callerScope = tenantScopeResolver.currentScope();
        UUID effectiveTenantId;
        if (callerScope == null) {
            // SUPER_ADMIN — if no tenantId param, aggregate platform-wide.
            effectiveTenantId = tenantId;
        } else if (TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE.equals(callerScope)) {
            // Fail-closed: empty stats
            return ResponseEntity.ok(verificationService.getVerificationStats(
                    TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE));
        } else {
            effectiveTenantId = callerScope;
        }
        return ResponseEntity.ok(verificationService.getVerificationStats(effectiveTenantId));
    }

    /**
     * Lists verification sessions. Tenant-scoped.
     */
    @GetMapping("/sessions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<VerificationSessionResponse>> listSessions(
            @RequestParam(required = false) UUID tenantId) {
        UUID callerScope = tenantScopeResolver.currentScope();
        UUID effectiveTenantId;
        if (callerScope == null) {
            effectiveTenantId = tenantId;
        } else if (TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE.equals(callerScope)) {
            return ResponseEntity.ok(List.of());
        } else {
            effectiveTenantId = callerScope;
        }
        return ResponseEntity.ok(verificationService.listSessions(effectiveTenantId));
    }

    /**
     * Returns a user's verification status + session history. S2 fix —
     * object-level authz inside {@link ManageVerificationService#getUserVerificationStatus}
     * confirms the target user's tenant is in the caller's scope
     * ({@code tenantScopeResolver.canAccessTenant(...)}; ROOT/SUPER_ADMIN
     * unrestricted), else 403. Without it any authenticated caller could read
     * any user's verification history by guessing their id (read-side IDOR).
     */
    @GetMapping("/results/{userId}")
    @PreAuthorize("@rbac.hasPermission('verification:read')")
    public ResponseEntity<VerificationStatusResponse> getUserVerificationStatus(@PathVariable UUID userId) {
        return ResponseEntity.ok(verificationService.getUserVerificationStatus(userId));
    }

    @PostMapping("/sessions/{id}/steps/{stepNumber}/review")
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN', 'ROLE_TENANT_ADMIN')")
    public ResponseEntity<VerificationStepResultResponse> reviewStep(
            @PathVariable UUID id,
            @PathVariable int stepNumber,
            @Valid @RequestBody ReviewVerificationStepCommand command) {
        return ResponseEntity.ok(
                verificationService.reviewStep(id, stepNumber, command.approved(), command.notes()));
    }
}
