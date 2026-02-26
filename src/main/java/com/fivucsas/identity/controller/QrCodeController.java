package com.fivucsas.identity.controller;

import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/qr")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "QR Code Authentication", description = "QR code generation and invalidation for authentication")
public class QrCodeController {

    private final QrCodeService qrCodeService;

    @PostMapping("/generate/{userId}")
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

    @DeleteMapping("/{token}")
    @Operation(summary = "Invalidate a QR authentication token")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> invalidateQrToken(@PathVariable String token) {
        log.info("QR token invalidation request");

        qrCodeService.invalidateToken(token);

        return ResponseEntity.noContent().build();
    }
}
