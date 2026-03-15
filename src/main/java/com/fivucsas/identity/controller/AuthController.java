package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.command.LogoutCommand;
import com.fivucsas.identity.application.dto.command.RefreshTokenCommand;
import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.*;
import com.fivucsas.identity.dto.AuthResponse;
import com.fivucsas.identity.dto.LoginRequest;
import com.fivucsas.identity.dto.RefreshTokenRequest;
import com.fivucsas.identity.dto.RegisterRequest;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.security.RateLimitService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller for authentication endpoints.
 *
 * Refactored to use Hexagonal Architecture input ports (use cases)
 * instead of directly calling services.
 *
 * Following principles:
 * - Adapter Pattern: REST adapter calling input ports
 * - Dependency Inversion: Depends on abstractions (use cases), not implementations
 * - Single Responsibility: Only handles HTTP concerns, delegates to use cases
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication endpoints")
public class AuthController {

    private final RegisterUserUseCase registerUserUseCase;
    private final AuthenticateUserUseCase authenticateUserUseCase;
    private final RefreshTokenUseCase refreshTokenUseCase;
    private final LogoutUserUseCase logoutUserUseCase;
    private final GetCurrentUserUseCase getCurrentUserUseCase;
    private final UserRepository userRepository;
    private final OtpService otpService;
    private final EmailService emailService;
    private final SmsService smsService;
    private final PasswordEncoder passwordEncoder;
    private final RateLimitService rateLimitService;

    private static final String EMAIL_VERIFY_OTP_PREFIX = "email-verify:";
    private static final String PHONE_VERIFY_OTP_PREFIX = "phone-verify:";

    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        log.info("Register request received for email: {}", request.getEmail());

        RegisterUserCommand command = RegisterUserCommand.builder()
            .email(request.getEmail())
            .password(request.getPassword())
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .ipAddress(getClientIP(httpRequest))
            .userAgent(getUserAgent(httpRequest))
            .build();

        AuthenticationResponse response = registerUserUseCase.execute(command);

        return ResponseEntity.ok(mapToAuthResponse(response));
    }

    @PostMapping("/login")
    @Operation(summary = "Login with email and password")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        log.info("Login request received for email: {}", request.getEmail());

        AuthenticateUserCommand command = AuthenticateUserCommand.builder()
            .email(request.getEmail())
            .password(request.getPassword())
            .ipAddress(getClientIP(httpRequest))
            .userAgent(getUserAgent(httpRequest))
            .build();

        AuthenticationResponse response = authenticateUserUseCase.execute(command);

        return ResponseEntity.ok(mapToAuthResponse(response));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token using refresh token")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        log.info("Refresh token request received");

        RefreshTokenCommand command = RefreshTokenCommand.builder()
            .refreshToken(request.getRefreshToken())
            .ipAddress(getClientIP(httpRequest))
            .userAgent(getUserAgent(httpRequest))
            .build();

        AuthenticationResponse response = refreshTokenUseCase.execute(command);

        return ResponseEntity.ok(mapToAuthResponse(response));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout and revoke refresh token", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Void> logout(
            @Valid @RequestBody RefreshTokenRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Logout request received");

        String authHeader = httpRequest.getHeader("Authorization");
        String accessToken = (authHeader != null && authHeader.startsWith("Bearer "))
                ? authHeader.substring(7) : null;

        LogoutCommand command = LogoutCommand.builder()
            .refreshToken(request.getRefreshToken())
            .currentUserEmail(authentication.getName())
            .accessToken(accessToken)
            .build();

        logoutUserUseCase.execute(command);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    @Operation(summary = "Get current authenticated user", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<UserResponse> getCurrentUser(Authentication authentication) {
        log.info("Get current user request");

        GetUserByEmailQuery query = GetUserByEmailQuery.builder()
            .email(authentication.getName())
            .build();

        UserResponse response = getCurrentUserUseCase.execute(query);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Request a password reset code via email")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) {
        String email = request.get("email");
        log.info("Forgot password request for email: {}", email);

        if (email == null || email.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Email is required"));
        }

        String clientIp = getClientIP(httpRequest);
        if (!rateLimitService.allowPasswordResetAttempt(clientIp)) {
            return ResponseEntity.status(429).body(Map.of("message", "Too many password reset requests. Please try again later."));
        }

        // Always return success to prevent email enumeration
        userRepository.findByEmail(email).ifPresent(user -> {
            String otpKey = "password-reset:" + user.getId();
            String code = otpService.generate(otpKey);
            emailService.sendOtp(email, code);
            log.info("Password reset code sent to: {}", email);
        });

        return ResponseEntity.ok(Map.of("message", "If an account with that email exists, a reset code has been sent."));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password using the code from email")
    public ResponseEntity<Map<String, String>> resetPassword(
            @RequestBody Map<String, String> request) {
        String email = request.get("email");
        String code = request.get("code");
        String newPassword = request.get("newPassword");
        log.info("Reset password request for email: {}", email);

        if (email == null || code == null || newPassword == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "email, code, and newPassword are required"));
        }

        if (newPassword.length() < 8) {
            return ResponseEntity.badRequest().body(Map.of("message", "Password must be at least 8 characters"));
        }

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid email or reset code"));
        }

        String otpKey = "password-reset:" + user.getId();
        if (!otpService.validate(otpKey, code)) {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid or expired reset code"));
        }

        user.updatePassword(newPassword, passwordEncoder);
        userRepository.save(user);
        log.info("Password successfully reset for user: {}", user.getId());

        return ResponseEntity.ok(Map.of("message", "Password has been reset successfully"));
    }

    @PostMapping("/send-email-verification")
    @Operation(summary = "Send email verification code", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, String>> sendEmailVerification(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UserNotFoundException(authentication.getName()));

        if (user.isEmailVerified()) {
            return ResponseEntity.ok(Map.of("message", "Email is already verified"));
        }

        String code = otpService.generate(EMAIL_VERIFY_OTP_PREFIX + user.getId());
        emailService.sendOtp(user.getEmail(), code);
        log.info("Email verification code sent to: {}", user.getEmail());

        return ResponseEntity.ok(Map.of("message", "Verification code sent to your email"));
    }

    @PostMapping("/verify-email")
    @Operation(summary = "Verify email address using OTP code", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, Object>> verifyEmail(
            @RequestBody Map<String, String> request,
            Authentication authentication) {
        String code = request.get("code");
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "code is required"));
        }

        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UserNotFoundException(authentication.getName()));

        if (user.isEmailVerified()) {
            return ResponseEntity.ok(Map.of("success", true, "message", "Email is already verified"));
        }

        boolean valid = otpService.validate(EMAIL_VERIFY_OTP_PREFIX + user.getId(), code);
        if (!valid) {
            return ResponseEntity.ok(Map.of("success", false, "message", "Invalid or expired verification code"));
        }

        user.verifyEmail();
        userRepository.save(user);
        log.info("Email verified for user: {}", user.getId());

        return ResponseEntity.ok(Map.of("success", true, "message", "Email verified successfully"));
    }

    @PostMapping("/send-phone-verification")
    @Operation(summary = "Send phone verification code via SMS", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, String>> sendPhoneVerification(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UserNotFoundException(authentication.getName()));

        if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("message", "No phone number configured on this account"));
        }

        if (user.isPhoneVerified()) {
            return ResponseEntity.ok(Map.of("message", "Phone number is already verified"));
        }

        String code = otpService.generate(PHONE_VERIFY_OTP_PREFIX + user.getId());
        smsService.sendOtp(user.getPhoneNumber(), code);
        log.info("Phone verification code sent to user: {}", user.getId());

        return ResponseEntity.ok(Map.of("message", "Verification code sent via SMS"));
    }

    @PostMapping("/verify-phone")
    @Operation(summary = "Verify phone number using OTP code", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, Object>> verifyPhone(
            @RequestBody Map<String, String> request,
            Authentication authentication) {
        String code = request.get("code");
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "code is required"));
        }

        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UserNotFoundException(authentication.getName()));

        if (user.isPhoneVerified()) {
            return ResponseEntity.ok(Map.of("success", true, "message", "Phone number is already verified"));
        }

        boolean valid = otpService.validate(PHONE_VERIFY_OTP_PREFIX + user.getId(), code);
        if (!valid) {
            return ResponseEntity.ok(Map.of("success", false, "message", "Invalid or expired verification code"));
        }

        user.verifyPhone();
        userRepository.save(user);
        log.info("Phone verified for user: {}", user.getId());

        return ResponseEntity.ok(Map.of("success", true, "message", "Phone number verified successfully"));
    }

    @GetMapping("/health")
    @Operation(summary = "Health check")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Auth service is healthy");
    }

    // Mapping methods (API DTOs <-> Application DTOs)

    private AuthResponse mapToAuthResponse(AuthenticationResponse response) {
        return AuthResponse.of(
            response.getAccessToken(),
            response.getRefreshToken(),
            response.getExpiresIn(),
            response.getUser()
        );
    }

    // Utility methods

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }

    private String getUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "Unknown";
    }
}
