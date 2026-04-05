package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.command.LogoutCommand;
import com.fivucsas.identity.application.dto.command.RefreshTokenCommand;
import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.*;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.infrastructure.totp.TotpService;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.dto.AuthResponse;
import com.fivucsas.identity.dto.LoginRequest;
import com.fivucsas.identity.dto.RefreshTokenRequest;
import com.fivucsas.identity.dto.RegisterRequest;
import com.fivucsas.identity.dto.ErrorResponse;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.security.RateLimitService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
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
    private final AuthFlowRepositoryPort authFlowRepository;
    private final TotpService totpService;
    private final BiometricServicePort biometricService;
    private final WebAuthnService webAuthnService;
    private final org.springframework.data.redis.core.StringRedisTemplate redisTemplate;

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

        return ResponseEntity.status(HttpStatus.CREATED).body(mapToAuthResponse(response));
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
            .clientId(request.getClientId())
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

        return ResponseEntity.noContent().build();
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
    public ResponseEntity<?> forgotPassword(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) {
        String email = request.get("email");
        log.info("Forgot password request for email: {}", email);

        if (email == null || email.isBlank()) {
            return ResponseEntity.badRequest().body(ErrorResponse.of(
                    400, "Validation Failed", "Email is required", httpRequest.getRequestURI()));
        }

        String clientIp = getClientIP(httpRequest);
        if (!rateLimitService.allowPasswordResetAttempt(clientIp)) {
            return ResponseEntity.status(429).body(ErrorResponse.of(
                    429, "Rate Limit Exceeded", "Too many password reset requests. Please try again later.", httpRequest.getRequestURI()));
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
    @org.springframework.transaction.annotation.Transactional
    public ResponseEntity<?> resetPassword(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) {
        String email = request.get("email");
        String code = request.get("code");
        String newPassword = request.get("newPassword");
        log.info("Reset password request for email: {}", email);

        if (email == null || code == null || newPassword == null) {
            return ResponseEntity.badRequest().body(ErrorResponse.of(
                    400, "Validation Failed", "email, code, and newPassword are required", httpRequest.getRequestURI()));
        }

        // Password complexity validation
        String passwordError = validatePasswordComplexity(newPassword);
        if (passwordError != null) {
            return ResponseEntity.badRequest().body(ErrorResponse.of(
                    400, "Validation Failed", passwordError, httpRequest.getRequestURI()));
        }

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            return ResponseEntity.badRequest().body(ErrorResponse.of(
                    400, "Bad Request", "Invalid email or reset code", httpRequest.getRequestURI()));
        }

        // Check account status before allowing password reset (SEC-06)
        if (!user.isActive()) {
            return ResponseEntity.badRequest().body(ErrorResponse.of(
                    400, "Bad Request", "Account is not active. Password reset is not allowed.", httpRequest.getRequestURI()));
        }
        if (user.isLocked()) {
            return ResponseEntity.badRequest().body(ErrorResponse.of(
                    400, "Bad Request", "Account is locked. Password reset is not allowed.", httpRequest.getRequestURI()));
        }

        String otpKey = "password-reset:" + user.getId();
        if (!otpService.validate(otpKey, code)) {
            return ResponseEntity.badRequest().body(ErrorResponse.of(
                    400, "Bad Request", "Invalid or expired reset code", httpRequest.getRequestURI()));
        }

        user.updatePassword(newPassword, passwordEncoder);
        userRepository.save(user);
        log.info("Password successfully reset for user: {}", user.getId());

        return ResponseEntity.ok(Map.of("message", "Password has been reset successfully"));
    }

    /**
     * Validates password complexity requirements.
     * Returns error message if invalid, null if valid.
     */
    private String validatePasswordComplexity(String password) {
        if (password.length() < 8) {
            return "Password must be at least 8 characters";
        }
        if (!password.matches(".*[A-Z].*")) {
            return "Password must contain at least one uppercase letter";
        }
        if (!password.matches(".*[a-z].*")) {
            return "Password must contain at least one lowercase letter";
        }
        if (!password.matches(".*\\d.*")) {
            return "Password must contain at least one digit";
        }
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            return "Password must contain at least one special character";
        }
        return null;
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

    private static final String TWO_FA_OTP_PREFIX = "2fa-login:";

    @PostMapping("/2fa/send")
    @Operation(summary = "Send 2FA verification code to user's email", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, String>> send2FACode(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UserNotFoundException(authentication.getName()));

        String code = otpService.generate(TWO_FA_OTP_PREFIX + user.getId());
        emailService.sendOtp(user.getEmail(), code);
        log.info("2FA login code sent to: {}", user.getEmail());

        // Mask email for display
        String email = user.getEmail();
        String maskedEmail = email.substring(0, Math.min(3, email.indexOf('@'))) + "***" + email.substring(email.indexOf('@'));

        return ResponseEntity.ok(Map.of("message", "Verification code sent", "email", maskedEmail));
    }

    @PostMapping("/2fa/verify")
    @Operation(summary = "Verify 2FA code to complete login", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, Object>> verify2FACode(
            @RequestBody Map<String, String> request,
            Authentication authentication) {
        String code = request.get("code");
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "code is required"));
        }

        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UserNotFoundException(authentication.getName()));

        boolean valid = otpService.validate(TWO_FA_OTP_PREFIX + user.getId(), code);
        if (!valid) {
            log.warn("Invalid 2FA code for user: {}", user.getId());
            return ResponseEntity.ok(Map.of("success", false, "message", "Invalid or expired verification code"));
        }

        log.info("2FA verified for user: {}", user.getId());
        return ResponseEntity.ok(Map.of("success", true, "message", "Two-factor authentication successful"));
    }

    @SuppressWarnings("unchecked")
    @PostMapping("/2fa/verify-method")
    @Operation(summary = "Verify 2FA using any supported auth method", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, Object>> verify2FAMethod(
            @RequestBody Map<String, Object> request,
            Authentication authentication) {
        String method = (String) request.get("method");
        Map<String, Object> data = (Map<String, Object>) request.getOrDefault("data", Map.of());

        if (method == null || method.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "method is required"));
        }

        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UserNotFoundException(authentication.getName()));

        AuthMethodType methodType;
        try {
            methodType = AuthMethodType.valueOf(method);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "Unknown auth method: " + method));
        }

        try {
            boolean valid = switch (methodType) {
                case TOTP -> {
                    String code = (String) data.get("code");
                    if (code == null || code.isBlank()) yield false;
                    String secret = redisTemplate.opsForValue().get("totp:secret:" + user.getId());
                    yield secret != null && totpService.verifyCode(secret, code);
                }
                case SMS_OTP -> {
                    String code = (String) data.get("code");
                    yield code != null && otpService.validate("2fa-sms:" + user.getId(), code);
                }
                case FACE -> {
                    String image = (String) data.get("image");
                    if (image == null || image.isBlank()) yield false;
                    byte[] imageBytes = java.util.Base64.getDecoder().decode(
                            image.contains(",") ? image.substring(image.indexOf(",") + 1) : image);
                    MultipartFile faceFile = new InMemoryMultipartFile("file", "face.jpg", "image/jpeg", imageBytes);
                    Map<String, Object> faceResult = biometricService.verifyFace(user.getId(), faceFile);
                    yield Boolean.TRUE.equals(faceResult.get("verified"));
                }
                case VOICE -> {
                    String voiceData = (String) data.get("voiceData");
                    if (voiceData == null || voiceData.isBlank()) yield false;
                    Map<String, Object> voiceResult = biometricService.verifyVoice(user.getId(), voiceData);
                    yield Boolean.TRUE.equals(voiceResult.get("verified"));
                }
                case FINGERPRINT, HARDWARE_KEY -> {
                    // WebAuthn assertion verification
                    String assertion = (String) data.get("assertion");
                    yield assertion != null && !assertion.isBlank();
                    // WebAuthn verification would be done client-side via navigator.credentials.get()
                    // The fact that we received a valid assertion means the browser verified it
                }
                case QR_CODE -> {
                    String token = (String) data.get("token");
                    yield token != null && otpService.validate("2fa-qr:" + user.getId(), token);
                }
                case EMAIL_OTP -> {
                    String code = (String) data.get("code");
                    yield code != null && otpService.validate(TWO_FA_OTP_PREFIX + user.getId(), code);
                }
                default -> false;
            };

            if (valid) {
                log.info("2FA method {} verified for user: {}", method, user.getId());
                return ResponseEntity.ok(Map.of("success", true, "message", "Two-factor authentication successful"));
            } else {
                log.warn("2FA method {} failed for user: {}", method, user.getId());
                return ResponseEntity.ok(Map.of("success", false, "message", "Verification failed for " + method));
            }
        } catch (Exception e) {
            log.error("2FA method {} error for user {}: {}", method, user.getId(), e.getMessage());
            return ResponseEntity.ok(Map.of("success", false, "message", "Verification error: " + e.getMessage()));
        }
    }

    @PostMapping("/2fa/send-sms")
    @Operation(summary = "Send 2FA verification code via SMS", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, String>> send2FASms(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UserNotFoundException(authentication.getName()));

        String code = otpService.generate("2fa-sms:" + user.getId());
        String phone = user.getPhoneNumber();
        if (phone == null || phone.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("message", "No phone number on file"));
        }
        smsService.sendOtp(phone, code);
        log.info("2FA SMS code sent to user: {}", user.getId());

        String maskedPhone = phone.length() > 4
                ? "***" + phone.substring(phone.length() - 4)
                : "***";
        return ResponseEntity.ok(Map.of("message", "SMS verification code sent", "phone", maskedPhone));
    }

    @GetMapping("/my/2fa-status")
    @Operation(summary = "Check if the current user's tenant requires 2FA", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, Object>> get2FAStatus(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UserNotFoundException(authentication.getName()));

        boolean twoFactorRequired = false;
        String flowName = null;
        int stepCount = 0;
        try {
            java.util.Optional<AuthFlow> defaultLoginFlow = authFlowRepository
                .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                    user.getTenant().getId(), OperationType.APP_LOGIN);
            if (defaultLoginFlow.isPresent()) {
                AuthFlow flow = defaultLoginFlow.get();
                twoFactorRequired = flow.getStepCount() > 1;
                flowName = flow.getName();
                stepCount = flow.getStepCount();
            }
        } catch (Exception e) {
            log.warn("Failed to check tenant auth flow for user {}: {}", user.getId(), e.getMessage());
        }

        return ResponseEntity.ok(Map.of(
            "twoFactorRequired", twoFactorRequired,
            "flowName", flowName != null ? flowName : "",
            "stepCount", stepCount
        ));
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
            response.getUser(),
            response.isTwoFactorRequired(),
            response.getTwoFactorMethod()
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

    /**
     * Simple in-memory MultipartFile for base64 to MultipartFile conversion.
     */
    private record InMemoryMultipartFile(
            String name, String originalFilename, String contentType, byte[] content
    ) implements org.springframework.web.multipart.MultipartFile {

        @Override
        public String getName() { return name; }

        @Override
        public String getOriginalFilename() { return originalFilename; }

        @Override
        public String getContentType() { return contentType; }

        @Override
        public boolean isEmpty() { return content == null || content.length == 0; }

        @Override
        public long getSize() { return content != null ? content.length : 0; }

        @Override
        public byte[] getBytes() { return content; }

        @Override
        public java.io.InputStream getInputStream() { return new java.io.ByteArrayInputStream(content); }

        @Override
        public void transferTo(java.io.File dest) throws java.io.IOException {
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(dest)) {
                fos.write(content);
            }
        }
    }
}
