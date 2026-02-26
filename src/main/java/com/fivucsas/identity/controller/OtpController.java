package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/otp")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OTP Authentication", description = "Standalone OTP send and verify endpoints for email and SMS")
public class OtpController {

    private static final String EMAIL_OTP_PREFIX = "otp:email:";
    private static final String SMS_OTP_PREFIX = "otp:sms:";

    private final OtpService otpService;
    private final EmailService emailService;
    private final SmsService smsService;
    private final UserRepository userRepository;

    @PostMapping("/email/send/{userId}")
    @Operation(summary = "Send an OTP code via email to the user")
    @PreAuthorize("hasAuthority('otp:send') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> sendEmailOtp(@PathVariable UUID userId) {
        log.info("Email OTP send request for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));

        String code = otpService.generate(EMAIL_OTP_PREFIX + userId);
        emailService.sendOtp(user.getEmail(), code);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "OTP sent to email",
                "expiresInSeconds", 300
        ));
    }

    @PostMapping("/email/verify/{userId}")
    @Operation(summary = "Verify an email OTP code")
    @PreAuthorize("hasAuthority('otp:verify') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> verifyEmailOtp(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {
        log.info("Email OTP verify request for user: {}", userId);

        String code = request.get("code");
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "code is required"));
        }

        boolean valid = otpService.validate(EMAIL_OTP_PREFIX + userId, code);

        return ResponseEntity.ok(Map.of(
                "success", valid,
                "message", valid ? "OTP verified successfully" : "Invalid or expired OTP code"
        ));
    }

    @PostMapping("/sms/send/{userId}")
    @Operation(summary = "Send an OTP code via SMS to the user")
    @PreAuthorize("hasAuthority('otp:send') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> sendSmsOtp(@PathVariable UUID userId) {
        log.info("SMS OTP send request for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));

        if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "User does not have a phone number configured"
            ));
        }

        String code = otpService.generate(SMS_OTP_PREFIX + userId);
        smsService.sendOtp(user.getPhoneNumber(), code);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "OTP sent via SMS",
                "expiresInSeconds", 300
        ));
    }

    @PostMapping("/sms/verify/{userId}")
    @Operation(summary = "Verify an SMS OTP code")
    @PreAuthorize("hasAuthority('otp:verify') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> verifySmsOtp(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {
        log.info("SMS OTP verify request for user: {}", userId);

        String code = request.get("code");
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "code is required"));
        }

        boolean valid = otpService.validate(SMS_OTP_PREFIX + userId, code);

        return ResponseEntity.ok(Map.of(
                "success", valid,
                "message", valid ? "OTP verified successfully" : "Invalid or expired OTP code"
        ));
    }
}
