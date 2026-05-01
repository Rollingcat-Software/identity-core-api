package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.infrastructure.sms.VerifiableSmsService;
import com.fivucsas.identity.infrastructure.totp.TotpService;
import com.fivucsas.identity.security.TotpSecretCipher;
import com.fivucsas.identity.domain.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.text.Normalizer;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

/**
 * REST controller for OTP and TOTP authentication endpoints.
 *
 * Merges: OtpController (email/SMS OTP) + TotpController (TOTP setup/verify)
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OTP Authentication", description = "OTP (email/SMS) and TOTP setup, verification endpoints")
public class OtpController {

    private static final String EMAIL_OTP_PREFIX = "otp:email:";
    private static final String SMS_OTP_PREFIX = "otp:sms:";
    private static final String TOTP_KEY_PREFIX = "totp:secret:";

    private final OtpService otpService;
    private final EmailService emailService;
    private final SmsService smsService;
    private final TotpService totpService;
    private final UserRepository userRepository;
    private final StringRedisTemplate redisTemplate;
    private final TotpSecretCipher totpSecretCipher;

    /**
     * Normalize an OTP code coming from a user-typed input or carrier-relayed
     * SMS. Strips zero-width / bidi formatting marks (some carriers and IMEs
     * inject these), NFC-normalizes Unicode digits, and trims surrounding
     * whitespace. Without this, a code visually identical to the stored value
     * compares non-equal because of an invisible U+200E / U+200F / U+FEFF.
     *
     * @return null if the input is null/blank after normalization
     */
    static String normalizeCode(String raw) {
        if (raw == null) return null;
        String stripped = raw
                // Zero-width + BOM + bidi formatting marks
                .replaceAll("[\\u200B-\\u200F\\u202A-\\u202E\\u2060\\uFEFF]", "")
                .trim();
        if (stripped.isEmpty()) return null;
        return Normalizer.normalize(stripped, Normalizer.Form.NFKC);
    }

    // --- /api/v1/otp endpoints ---

    @PostMapping("/api/v1/otp/email/send/{userId}")
    @Operation(summary = "Send an OTP code via email to the user")
    @PreAuthorize("hasAuthority('otp:send') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> sendEmailOtp(@PathVariable UUID userId) {
        log.info("Email OTP send request for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        String code = otpService.generate(EMAIL_OTP_PREFIX + userId);
        emailService.sendOtp(user.getEmail(), code);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "OTP sent to email",
                "expiresInSeconds", 300
        ));
    }

    @PostMapping("/api/v1/otp/email/verify/{userId}")
    @Operation(summary = "Verify an email OTP code")
    @PreAuthorize("hasAuthority('otp:verify') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> verifyEmailOtp(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {
        log.info("Email OTP verify request for user: {}", userId);

        String code = normalizeCode(request.get("code"));
        if (code == null) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "code is required"));
        }

        boolean valid = otpService.validate(EMAIL_OTP_PREFIX + userId, code);
        if (!valid) {
            log.warn("Email OTP mismatch for user: {} (reason=OTP_MISMATCH_OR_EXPIRED)", userId);
        }

        return ResponseEntity.ok(Map.of(
                "success", valid,
                "message", valid ? "OTP verified successfully" : "Invalid or expired OTP code"
        ));
    }

    @PostMapping("/api/v1/otp/sms/send/{userId}")
    @Operation(summary = "Send an OTP code via SMS to the user")
    @PreAuthorize("hasAuthority('otp:send') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> sendSmsOtp(@PathVariable UUID userId) {
        log.info("SMS OTP send request for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "User does not have a phone number configured"
            ));
        }

        // When the configured SmsService is a VerifiableSmsService (e.g. Twilio
        // Verify), the provider generates and stores the code itself — the
        // `code` argument to sendOtp(...) is intentionally ignored. We must NOT
        // pre-generate a local Redis code in that case, because verifySmsOtp
        // would otherwise compare the user-entered Twilio code against an
        // unrelated local code and always reject the first attempt.
        // (USER-BUG-4 root cause, 2026-05-01.)
        if (smsService instanceof VerifiableSmsService) {
            smsService.sendOtp(user.getPhoneNumber(), "");
            log.info("SMS OTP send delegated to VerifiableSmsService for user: {}", userId);
        } else {
            String code = otpService.generate(SMS_OTP_PREFIX + userId);
            smsService.sendOtp(user.getPhoneNumber(), code);
        }

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "OTP sent via SMS",
                "expiresInSeconds", 300
        ));
    }

    @PostMapping("/api/v1/otp/sms/verify/{userId}")
    @Operation(summary = "Verify an SMS OTP code")
    @PreAuthorize("hasAuthority('otp:verify') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> verifySmsOtp(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {
        log.info("SMS OTP verify request for user: {}", userId);

        String code = normalizeCode(request.get("code"));
        if (code == null) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "code is required"));
        }

        boolean valid;
        if (smsService instanceof VerifiableSmsService verifiable) {
            // Provider-side verification (e.g. Twilio Verify). Look up the
            // phone number on the User record — that's the destination Twilio
            // sent the code to, and Twilio matches by `to` + `code`.
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UserNotFoundException(userId.toString()));
            String phoneNumber = user.getPhoneNumber();
            if (phoneNumber == null || phoneNumber.isBlank()) {
                log.warn("SMS OTP verify rejected for user: {} (reason=NO_PHONE)", userId);
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "message", "User does not have a phone number configured"
                ));
            }
            valid = verifiable.verifyCode(phoneNumber, code);
            if (!valid) {
                log.warn("SMS OTP mismatch for user: {} via VerifiableSmsService (reason=PROVIDER_REJECTED)", userId);
            }
        } else {
            valid = otpService.validate(SMS_OTP_PREFIX + userId, code);
            if (!valid) {
                log.warn("SMS OTP mismatch for user: {} via local OTP store (reason=OTP_MISMATCH_OR_EXPIRED)", userId);
            }
        }

        return ResponseEntity.ok(Map.of(
                "success", valid,
                "message", valid ? "OTP verified successfully" : "Invalid or expired OTP code"
        ));
    }

    // --- /api/v1/totp endpoints (merged from TotpController) ---

    @PostMapping("/api/v1/totp/setup/{userId}")
    @Operation(summary = "Set up TOTP for a user - generates secret and OTP auth URI")
    @PreAuthorize("hasAuthority('totp:setup') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> setupTotp(@PathVariable UUID userId) {
        log.info("TOTP setup request for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        String secret = totpService.generateSecret();
        String otpAuthUri = totpService.buildOtpAuthUri(secret, user.getEmail(), "FivucsasIdentity");

        String pendingKey = TOTP_KEY_PREFIX + "pending:" + userId;
        redisTemplate.opsForValue().set(pendingKey, secret, Duration.ofMinutes(10));

        return ResponseEntity.ok(Map.of(
                "secret", secret,
                "otpAuthUri", otpAuthUri,
                "message", "Scan the QR code with your authenticator app, then verify with a code"
        ));
    }

    @PostMapping("/api/v1/totp/verify-setup/{userId}")
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

        // Cache in Redis for fast lookups
        String activeKey = TOTP_KEY_PREFIX + userId;
        redisTemplate.opsForValue().set(activeKey, secret);
        redisTemplate.delete(pendingKey);

        // Persist to PostgreSQL (source of truth — survives Redis restarts).
        // BE-H3: secret is encrypted at-rest via TotpSecretCipher (AES-GCM-256).
        // Redis keeps plaintext (ephemeral cache). DB always stores enc:v1:... form.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));
        user.enable2FA(totpSecretCipher.encrypt(secret), null);
        userRepository.save(user);

        log.info("TOTP setup completed for user: {} (persisted to DB + Redis)", userId);
        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "TOTP successfully configured"
        ));
    }

    @GetMapping("/api/v1/totp/status/{userId}")
    @Operation(summary = "Check if TOTP is configured for a user")
    @PreAuthorize("hasAuthority('totp:read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> getTotpStatus(@PathVariable UUID userId) {
        // Check Redis first (fast path), then fall back to PostgreSQL (source of truth)
        String activeKey = TOTP_KEY_PREFIX + userId;
        boolean configured = Boolean.TRUE.equals(redisTemplate.hasKey(activeKey));

        if (!configured) {
            User user = userRepository.findById(userId).orElse(null);
            configured = user != null && user.is2faEnabled();
            // Re-cache in Redis if found in DB but missing from Redis.
            // BE-H3: decrypt DB value (may be legacy plaintext) before caching.
            if (configured) {
                String plaintext = totpSecretCipher.decryptIfNeeded(user.getTwoFactorSecret());
                redisTemplate.opsForValue().set(activeKey, plaintext);
                log.info("TOTP secret re-cached in Redis for user: {}", userId);
            }
        }

        return ResponseEntity.ok(Map.of(
                "userId", userId.toString(),
                "configured", configured
        ));
    }

    @DeleteMapping("/api/v1/totp/{userId}")
    @Operation(summary = "Revoke/disable TOTP for a user")
    @PreAuthorize("hasAuthority('totp:delete') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> revokeTotp(@PathVariable UUID userId) {
        log.info("TOTP revocation request for user: {}", userId);

        // Clear from Redis
        String activeKey = TOTP_KEY_PREFIX + userId;
        String pendingKey = TOTP_KEY_PREFIX + "pending:" + userId;
        redisTemplate.delete(activeKey);
        redisTemplate.delete(pendingKey);

        // Clear from PostgreSQL (source of truth)
        userRepository.findById(userId).ifPresent(user -> {
            user.disable2FA();
            userRepository.save(user);
        });

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "TOTP disabled successfully"
        ));
    }
}
