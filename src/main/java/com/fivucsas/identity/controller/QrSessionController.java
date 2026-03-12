package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.qrcode.QrSessionService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * QR session controller for cross-device login flow.
 *
 * Flow:
 * 1. Desktop/web client creates a session (POST /auth/qr/session) — public endpoint
 * 2. Client displays QR code and polls status (GET /auth/qr/session/{sessionId})
 * 3. Mobile user scans QR and approves (POST /auth/qr/session/{sessionId}/approve) — authenticated
 * 4. Desktop client receives tokens on next poll
 */
@RestController
@RequestMapping("/api/v1/auth/qr/session")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "QR Login Sessions", description = "Cross-device QR code login session management")
public class QrSessionController {

    private final QrSessionService qrSessionService;
    private final RbacAuthorizationService rbacService;

    public record QrSessionCreateRequest(String platform) {}

    public record QrSessionApproveRequest(String approverPlatform) {}

    @PostMapping
    @Operation(summary = "Create a new QR login session")
    public ResponseEntity<Map<String, Object>> createSession(
            @RequestBody(required = false) QrSessionCreateRequest request) {
        String platform = request != null ? request.platform() : "unknown";
        log.info("QR login session creation request from platform: {}", platform);

        Map<String, Object> session = qrSessionService.createSession(platform);
        return ResponseEntity.ok(session);
    }

    @GetMapping("/{sessionId}")
    @Operation(summary = "Get QR login session status (poll endpoint)")
    public ResponseEntity<Map<String, Object>> getSession(@PathVariable @NotBlank String sessionId) {
        Map<String, Object> session = qrSessionService.getSession(sessionId);
        return ResponseEntity.ok(session);
    }

    @PostMapping("/{sessionId}/approve")
    @Operation(summary = "Approve a QR login session (from authenticated mobile user)")
    public ResponseEntity<Map<String, Object>> approveSession(
            @PathVariable @NotBlank String sessionId,
            @RequestBody(required = false) QrSessionApproveRequest request) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

        log.info("QR session approve request: session={}, approver={}", sessionId, currentUser.getId());

        Map<String, Object> result = qrSessionService.approveSession(sessionId, currentUser.getId());
        return ResponseEntity.ok(result);
    }
}
