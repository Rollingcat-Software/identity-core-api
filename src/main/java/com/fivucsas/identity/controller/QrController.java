package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.QrSessionApproveRequest;
import com.fivucsas.identity.application.dto.command.QrSessionCreateRequest;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import com.fivucsas.identity.infrastructure.qrcode.QrSessionService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

/**
 * REST controller for QR code authentication.
 *
 * Merges: QrCodeController (/api/v1/qr/*) + QrSessionController (/api/v1/auth/qr/session/*)
 * Uses full path on each method.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "QR Authentication", description = "QR code generation, session and cross-device login")
public class QrController {

    private final QrCodeService qrCodeService;
    private final QrSessionService qrSessionService;
    private final RbacAuthorizationService rbacService;

    // --- /api/v1/qr endpoints (from QrCodeController) ---

    @PostMapping("/api/v1/qr/generate/{userId}")
    @Operation(summary = "Generate a QR authentication token for the user")
    @PreAuthorize("hasAuthority('qr:generate') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> generateQrToken(@PathVariable UUID userId) {
        log.info("QR token generation request for user: {}", userId);

        String token = qrCodeService.generateToken(userId);

        return ResponseEntity.ok(Map.of(
                "token", token,
                "expiresInSeconds", 300,
                "userId", userId.toString()
        ));
    }

    @DeleteMapping("/api/v1/qr/{token}")
    @Operation(summary = "Invalidate a QR authentication token")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> invalidateQrToken(@PathVariable String token) {
        log.info("QR token invalidation request");
        qrCodeService.invalidateToken(token);
        return ResponseEntity.noContent().build();
    }

    // --- /api/v1/auth/qr/session endpoints (from QrSessionController) ---

    @PostMapping("/api/v1/auth/qr/session")
    @Operation(summary = "Create a new QR login session")
    public ResponseEntity<Map<String, Object>> createSession(
            @RequestBody(required = false) QrSessionCreateRequest request) {
        String platform = request != null ? request.platform() : "unknown";
        log.info("QR login session creation request from platform: {}", platform);

        Map<String, Object> session = qrSessionService.createSession(platform);
        return ResponseEntity.ok(session);
    }

    @GetMapping("/api/v1/auth/qr/session/{sessionId}")
    @Operation(summary = "Get QR login session status (poll endpoint)")
    public ResponseEntity<Map<String, Object>> getSession(@PathVariable @NotBlank String sessionId) {
        Map<String, Object> session = qrSessionService.getSession(sessionId);
        return ResponseEntity.ok(session);
    }

    @PostMapping("/api/v1/auth/qr/session/{sessionId}/approve")
    @Operation(summary = "Approve a QR login session (from authenticated mobile user)")
    public ResponseEntity<Map<String, Object>> approveSession(
            @PathVariable @NotBlank String sessionId,
            @RequestBody(required = false) QrSessionApproveRequest request) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        log.info("QR session approve request: session={}, approver={}", sessionId, currentUser.getId());

        Map<String, Object> result = qrSessionService.approveSession(sessionId, currentUser.getId());
        return ResponseEntity.ok(result);
    }
}
