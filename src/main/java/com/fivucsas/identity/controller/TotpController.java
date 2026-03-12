package com.fivucsas.identity.controller;

import com.fivucsas.identity.infrastructure.totp.TotpService;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/totp")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "TOTP Authentication", description = "TOTP setup, verification, and management")
public class TotpController {

    private static final String TOTP_KEY_PREFIX = "totp:secret:";

    private final TotpService totpService;
    private final UserRepository userRepository;
    private final StringRedisTemplate redisTemplate;

    @PostMapping("/setup/{userId}")
    @Operation(summary = "Set up TOTP for a user - generates secret and OTP auth URI")
    @PreAuthorize("hasAuthority('totp:setup') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> setupTotp(@PathVariable UUID userId) {
        log.info("TOTP setup request for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        String secret = totpService.generateSecret();
        String otpAuthUri = totpService.buildOtpAuthUri(secret, user.getEmail(), "FivucsasIdentity");

        // Store secret temporarily until verified - 10 minute TTL
        String pendingKey = TOTP_KEY_PREFIX + "pending:" + userId;
        redisTemplate.opsForValue().set(pendingKey, secret, java.time.Duration.ofMinutes(10));

        return ResponseEntity.ok(Map.of(
                "secret", secret,
                "otpAuthUri", otpAuthUri,
                "message", "Scan the QR code with your authenticator app, then verify with a code"
        ));
    }

    @PostMapping("/verify-setup/{userId}")
    @Operation(summary = "Verify TOTP setup by providing an initial code from authenticator app")
    @PreAuthorize("hasAuthority('totp:setup') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> verifyTotpSetup(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {
        log.info("TOTP setup verification for user: {}", userId);

        String code = request.get("code");
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "code is required"
            ));
        }

        String pendingKey = TOTP_KEY_PREFIX + "pending:" + userId;
        String secret = redisTemplate.opsForValue().get(pendingKey);
        if (secret == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "No pending TOTP setup found. Please call /setup first."
            ));
        }

        boolean valid = totpService.verifyCode(secret, code);
        if (!valid) {
            return ResponseEntity.ok(Map.of(
                    "success", false,
                    "message", "Invalid TOTP code. Please try again."
            ));
        }

        // Code verified - persist the secret
        String activeKey = TOTP_KEY_PREFIX + userId;
        redisTemplate.opsForValue().set(activeKey, secret);
        redisTemplate.delete(pendingKey);

        log.info("TOTP setup completed for user: {}", userId);
        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "TOTP successfully configured"
        ));
    }

    @GetMapping("/status/{userId}")
    @Operation(summary = "Check if TOTP is configured for a user")
    @PreAuthorize("hasAuthority('totp:read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> getTotpStatus(@PathVariable UUID userId) {
        String activeKey = TOTP_KEY_PREFIX + userId;
        boolean configured = Boolean.TRUE.equals(redisTemplate.hasKey(activeKey));

        return ResponseEntity.ok(Map.of(
                "userId", userId.toString(),
                "configured", configured
        ));
    }

    @DeleteMapping("/{userId}")
    @Operation(summary = "Revoke/disable TOTP for a user")
    @PreAuthorize("hasAuthority('totp:delete') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> revokeTotp(@PathVariable UUID userId) {
        log.info("TOTP revocation request for user: {}", userId);

        String activeKey = TOTP_KEY_PREFIX + userId;
        String pendingKey = TOTP_KEY_PREFIX + "pending:" + userId;
        redisTemplate.delete(activeKey);
        redisTemplate.delete(pendingKey);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "TOTP disabled successfully"
        ));
    }
}
