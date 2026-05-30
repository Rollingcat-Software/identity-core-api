package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.ApproveLoginCreateRequest;
import com.fivucsas.identity.application.dto.command.ApproveLoginDecideRequest;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.infrastructure.approvelogin.ApproveLoginService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * No-Firebase number-matching approve-login.
 *
 * <p>Cross-device "approve this sign-in" flow that needs no push provider: an
 * unauthenticated client starts a session for an account and shows a two-digit
 * match number; an authenticated session of the same user lists its pending
 * requests, sees the number, and decides allow/deny; the original client polls
 * and receives minted tokens once approved.
 *
 * <p>Modeled on {@link QrController} + the QR session service. The anonymous
 * create + poll endpoints are added to {@code SecurityConfig} permitAll; the
 * pending-list + decide endpoints require an authenticated approver.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Approve Login", description = "No-Firebase number-matching cross-device login approval")
public class ApproveLoginController {

    private final ApproveLoginService approveLoginService;
    private final RbacAuthorizationService rbacService;

    @PostMapping("/api/v1/auth/approve-login/session")
    @Operation(summary = "Start a number-matching approve-login session for an account (anonymous)")
    public ResponseEntity<Map<String, Object>> createSession(
            @Valid @RequestBody ApproveLoginCreateRequest request,
            HttpServletRequest httpRequest) {
        String ip = clientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        log.info("Approve-login session create request from ip={}", ip);

        Map<String, Object> session = approveLoginService.createSession(request.email(), ip, userAgent);
        return ResponseEntity.ok(session);
    }

    @GetMapping("/api/v1/auth/approve-login/session/{sessionId}")
    @Operation(summary = "Poll an approve-login session status (anonymous)")
    public ResponseEntity<Map<String, Object>> getSession(@PathVariable @NotBlank String sessionId) {
        return ResponseEntity.ok(approveLoginService.getSession(sessionId));
    }

    @GetMapping("/api/v1/auth/approve-login/pending")
    @Operation(summary = "List the authenticated user's pending approve-login requests")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<Map<String, Object>>> listPending() {
        UUID approverId = rbacService.getCurrentUserId().orElseThrow(UnauthorizedException::new);
        return ResponseEntity.ok(approveLoginService.listPending(approverId));
    }

    @PostMapping("/api/v1/auth/approve-login/session/{sessionId}/decide")
    @Operation(summary = "Approve or deny an approve-login session (authenticated approver)")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> decide(
            @PathVariable @NotBlank String sessionId,
            @Valid @RequestBody ApproveLoginDecideRequest request,
            HttpServletRequest httpRequest) {
        UUID approverId = rbacService.getCurrentUserId().orElseThrow(UnauthorizedException::new);
        String ip = clientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        log.info("Approve-login decide request: session={}, approver={}, decision={}",
                sessionId, approverId, request.decision());

        Map<String, Object> result = approveLoginService.decide(
                sessionId, approverId, request.decision(), request.matchNumber(), ip, userAgent);
        return ResponseEntity.ok(result);
    }

    private static String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
