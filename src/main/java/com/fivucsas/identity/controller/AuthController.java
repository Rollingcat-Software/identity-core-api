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
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.dto.UserDto;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.repository.UserRepository;
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
    private final PasswordEncoder passwordEncoder;
    private final RateLimitService rateLimitService;

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
            Authentication authentication) {
        log.info("Logout request received");

        LogoutCommand command = LogoutCommand.builder()
            .refreshToken(request.getRefreshToken())
            .currentUserEmail(authentication.getName())
            .build();

        logoutUserUseCase.execute(command);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    @Operation(summary = "Get current authenticated user", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<UserDto> getCurrentUser(Authentication authentication) {
        log.info("Get current user request");

        GetUserByEmailQuery query = GetUserByEmailQuery.builder()
            .email(authentication.getName())
            .build();

        UserResponse response = getCurrentUserUseCase.execute(query);

        return ResponseEntity.ok(mapToUserDto(response));
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
            mapToUserDto(response.getUser())
        );
    }

    private UserDto mapToUserDto(UserResponse response) {
        return UserDto.builder()
            .id(response.getId())
            .email(response.getEmail())
            .firstName(response.getFirstName())
            .lastName(response.getLastName())
            .phoneNumber(response.getPhoneNumber())
            .address(response.getAddress())
            .idNumber(response.getIdNumber())
            .status(UserStatus.valueOf(response.getStatus()))
            .role(response.getRole())
            .roles(response.getRoles())
            .tenantId(response.getTenantId())
            .isBiometricEnrolled(response.isBiometricEnrolled())
            .enrolledAt(response.getEnrolledAt())
            .lastVerifiedAt(response.getLastVerifiedAt())
            .verificationCount(response.getVerificationCount())
            .createdAt(response.getCreatedAt())
            .updatedAt(response.getUpdatedAt())
            .build();
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
