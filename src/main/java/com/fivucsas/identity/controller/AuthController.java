package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.command.LogoutCommand;
import com.fivucsas.identity.application.dto.command.RefreshTokenCommand;
import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.LoginConfigResponse;
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
import com.fivucsas.identity.infrastructure.sms.VerifiableSmsService;
import com.fivucsas.identity.infrastructure.web.InMemoryMultipartFile;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.domain.exception.OtpAttemptsExhaustedException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.security.TotpSecretCipher;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.dto.AvailableMfaMethod;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.WebAuthnCredential;

import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.service.RefreshTokenService;

import java.util.*;

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
    private final MfaSessionRepository mfaSessionRepository;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final UserEnrollmentRepository userEnrollmentRepository;
    private final com.fivucsas.identity.application.service.EnrollmentHealthService enrollmentHealthService;
    private final TotpSecretCipher totpSecretCipher;
    private final com.fivucsas.identity.application.port.output.NfcCardRepositoryPort nfcCardRepository;
    private final com.fivucsas.identity.infrastructure.qrcode.QrCodeService qrCodeService;
    private final com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;
    private final com.fivucsas.identity.application.port.output.AuditLogPort auditLogPort;
    private final com.fivucsas.identity.application.service.mfa.VerifyMfaStepService verifyMfaStepService;
    private final com.fivucsas.identity.application.service.LoginConfigService loginConfigService;

    private static final String EMAIL_VERIFY_OTP_PREFIX = "email-verify:";
    private static final String PHONE_VERIFY_OTP_PREFIX = "phone-verify:";

    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        log.info("AUDIT: Register attempt — email={}, ip={}, userAgent={}",
                request.getEmail(), getClientIP(httpRequest), getUserAgent(httpRequest));

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
        log.info("AUDIT: Login attempt — email={}, ip={}, userAgent={}",
                request.getEmail(), getClientIP(httpRequest), getUserAgent(httpRequest));

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

    /**
     * Public, unauthenticated description of a tenant's default APP_LOGIN flow
     * (task #16 C). The login surface calls this BEFORE rendering to decide
     * which Layer-1 affordance to show (password field vs. passkey vs. approve-
     * on-another-device vs. an identifier-first OTP/biometric step) and how many
     * steps to expect. Exposes no internal IDs — see {@link LoginConfigResponse}.
     */
    @GetMapping("/login-config")
    @Operation(summary = "Public tenant login-flow config (Layer-1 methods + step count)")
    public ResponseEntity<LoginConfigResponse> loginConfig(
            @RequestParam(value = "tenantId", required = false) UUID tenantId,
            @RequestParam(value = "clientId", required = false) String clientId) {
        // The hosted login surface (verify.fivucsas.com) only carries the OIDC
        // client_id, not the internal tenant id — resolve the tenant from
        // oauth2_clients. The dashboard/widget pass tenantId directly.
        if (clientId != null && !clientId.isBlank()) {
            return loginConfigService.getLoginConfigByClientId(clientId)
                    .map(ResponseEntity::ok)
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "Unknown or tenant-less OAuth2 client"));
        }
        if (tenantId != null) {
            return ResponseEntity.ok(loginConfigService.getLoginConfig(tenantId));
        }
        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "Either tenantId or clientId is required");
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token using refresh token")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        log.info("AUDIT: Token refresh request — ip={}", getClientIP(httpRequest));

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
        log.info("AUDIT: Logout request — user={}, ip={}, userAgent={}",
                authentication.getName(), getClientIP(httpRequest), getUserAgent(httpRequest));

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
        log.info("AUDIT: Forgot password request — email={}, ip={}", email, getClientIP(httpRequest));

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
        log.info("AUDIT: Reset password request — email={}, ip={}", email, getClientIP(httpRequest));

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
        log.info("AUDIT: Password reset successful — userId={}, ip={}", user.getId(), getClientIP(httpRequest));

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
            // P1 hygiene 2026-05-07: invalid/expired OTP is an auth failure,
            // surface as 401 so observability tools (4xx-rate alerts, log
            // dashboards) and downstream HTTP clients see it as a failure
            // rather than a 200 with an embedded `success:false`.
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("success", false, "message", "Invalid or expired verification code"));
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
            // P1 hygiene 2026-05-07: invalid/expired OTP returns 401 so
            // observability tools see an auth failure (was 200/success:false).
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("success", false, "message", "Invalid or expired verification code"));
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
            log.warn("AUDIT: 2FA failed — method: EMAIL_OTP, reason: invalid_or_expired_otp, userId={}", user.getId());
            // P1 hygiene 2026-05-07: failed 2FA is auth failure → HTTP 401.
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("success", false, "message", "Invalid or expired verification code"));
        }

        log.info("AUDIT: 2FA verified — method: EMAIL_OTP, userId={}", user.getId());
        return ResponseEntity.ok(Map.of("success", true, "message", "Two-factor authentication successful"));
    }

    @SuppressWarnings("unchecked")
    @PostMapping("/2fa/verify-method")
    @Operation(summary = "Verify 2FA using any supported auth method", security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<Map<String, Object>> verify2FAMethod(
            @RequestBody Map<String, Object> request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
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
                    String secret = resolveTotpSecret(user);
                    // S13: single-use (anti-replay) verify bound to the user.
                    yield secret != null && totpService.verifyCodeForUser(user.getId(), secret, code);
                }
                case SMS_OTP -> {
                    String code = (String) data.get("code");
                    if (code == null || code.isBlank()) yield false;
                    if (smsService instanceof VerifiableSmsService verifiableSms) {
                        String phone = user.getPhoneNumber();
                        if (phone == null || phone.isBlank()) yield false;
                        yield verifiableSms.verifyCode(phone, code);
                    }
                    // SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §OTP-exhausted —
                    // propagate the NIST 800-63B 5-strike exhaustion so the user
                    // gets "request a new code" instead of waiting the full TTL.
                    OtpService.ValidationResult smsResult =
                            otpService.validateWithResult("2fa-sms:" + user.getId(), code);
                    if (smsResult.isExhausted()) {
                        throw new OtpAttemptsExhaustedException();
                    }
                    yield smsResult.isValid();
                }
                case FACE -> {
                    String image = (String) data.get("image");
                    if (image == null || image.isBlank()) yield false;
                    // Cache the user-id once — keeps the entity.User boundary surface
                    // (ArchUnit UserDomainBoundaryTest) to a single call site for FACE.
                    java.util.UUID faceUserId = user.getId();
                    byte[] imageBytes = java.util.Base64.getDecoder().decode(
                            image.contains(",") ? image.substring(image.indexOf(",") + 1) : image);
                    MultipartFile faceFile = new InMemoryMultipartFile(
                            "file", "face.jpg", "image/jpeg", imageBytes);
                    Map<String, Object> faceResult = biometricService.verifyFace(faceUserId, faceFile);
                    // Check spoof detection
                    String errorCode2fa = faceResult.get("error_code") instanceof String ec ? ec : null;
                    if ("SPOOF_DETECTED".equals(errorCode2fa)) {
                        log.warn("AUDIT: 2FA face spoof detected — userId={}, ip={}",
                                faceUserId, getClientIP(httpRequest));
                        yield false;
                    }
                    // SECURITY (P0-#10): trust ONLY the bio processor's `verified` field.
                    // No client-side confidence fallback — the bio processor already
                    // applies adaptive aging thresholds (VERIFICATION_THRESHOLD_AGED_*).
                    // See INVESTIGATION_FAILOPEN_2026-05-07.md F3.
                    Object verified2fa = faceResult.get("verified");
                    if (verified2fa == null) {
                        log.error("AUDIT: 2FA face verify missing `verified` field — userId={}, ip={}, rejecting",
                                faceUserId, getClientIP(httpRequest));
                        yield false;
                    }
                    yield Boolean.TRUE.equals(verified2fa)
                            || "true".equalsIgnoreCase(String.valueOf(verified2fa));
                }
                case VOICE -> {
                    String voiceData = (String) data.get("voiceData");
                    if (voiceData == null || voiceData.isBlank()) yield false;
                    Map<String, Object> voiceResult = biometricService.verifyVoice(user.getId(), voiceData);
                    yield Boolean.TRUE.equals(voiceResult.get("verified"));
                }
                case FINGERPRINT, HARDWARE_KEY -> {
                    // P0 FIX (Investigation 2026-05-07 F1): the previous implementation
                    // accepted ANY non-empty `assertion` string as a passing 2FA factor —
                    // no signature check, no credentialId lookup, no public-key
                    // verification, no sign-counter validation. This bypassed 2FA
                    // entirely for any logged-in user whose flow landed here.
                    //
                    // The legacy /2fa/verify-method route does NOT carry a
                    // server-side WebAuthn challenge handshake (no MfaSession,
                    // no /webauthn/authenticate-options call), so we cannot
                    // safely verify here even with the canonical
                    // WebAuthnVerifySupport.verifyAssertion(...).
                    //
                    // We FAIL CLOSED. Callers MUST migrate to either:
                    //   - POST /api/v1/auth/mfa/step (N-step flow → WebAuthnVerifySupport)
                    //   - POST /api/v1/webauthn/authenticate (post-login WebAuthn)
                    // both of which perform full RFC 8176-compliant verification.
                    // Log user identity via authentication name (email) to avoid a
                    // new entity.User.getId() call site — the UserDomainBoundary
                    // ArchUnit ratchet (ANALYSIS_2026-05-02_USER_DOMAIN_AND_JWT_ROTATION.md)
                    // pins existing call sites and rejects new ones from controller.
                    log.warn("AUDIT: 2FA FINGERPRINT/HARDWARE_KEY rejected on legacy /2fa/verify-method — " +
                            "legacy route cannot verify WebAuthn assertions (no challenge handshake). " +
                            "user={}, method={}", authentication.getName(), method);
                    yield false;
                }
                case QR_CODE -> {
                    String token = (String) data.get("token");
                    yield token != null && otpService.validate("2fa-qr:" + user.getId(), token);
                }
                case EMAIL_OTP -> {
                    String code = (String) data.get("code");
                    if (code == null || code.isBlank()) yield false;
                    // SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §OTP-exhausted —
                    // propagate the NIST 800-63B 5-strike exhaustion so the user
                    // gets "request a new code" instead of waiting the full TTL.
                    OtpService.ValidationResult emailResult =
                            otpService.validateWithResult(TWO_FA_OTP_PREFIX + user.getId(), code);
                    if (emailResult.isExhausted()) {
                        throw new OtpAttemptsExhaustedException();
                    }
                    yield emailResult.isValid();
                }
                default -> false;
            };

            String clientIp = getClientIP(httpRequest);
            String ua = getUserAgent(httpRequest);

            if (valid) {
                log.info("AUDIT: 2FA verified — method: {}, userId={}, ip={}, userAgent={}",
                        method, user.getId(), clientIp, ua);
                auditLogPort.logTwoFactorVerified(user.getId().toString(), method, clientIp, ua);
                return ResponseEntity.ok(Map.of("success", true, "message", "Two-factor authentication successful"));
            } else {
                String reason = resolveFailureReason(methodType, data);
                log.warn("AUDIT: 2FA failed — method: {}, reason: {}, userId={}, ip={}, userAgent={}",
                        method, reason, user.getId(), clientIp, ua);
                auditLogPort.logTwoFactorFailed(user.getId().toString(), method, reason, clientIp, ua);
                // P1 hygiene 2026-05-07: failed 2FA verification is an auth
                // failure → HTTP 401 (was 200/success:false, hiding from
                // 4xx-rate observability).
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("success", false, "message", "Verification failed for " + method));
            }
        } catch (OtpAttemptsExhaustedException e) {
            // SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §OTP-exhausted —
            // NIST 800-63B 5-strike trip is a known/contracted state, not a
            // 5xx error. Rethrow so GlobalExceptionHandler maps it to HTTP 429
            // + Retry-After + action:resend (matches OtpController contract).
            // Cache user-id once so this branch does not add net-new
            // entity.User.getId() call-sites to the UserDomainBoundary
            // ArchUnit baseline (matches the FACE case pattern above).
            String clientIp = getClientIP(httpRequest);
            String ua = getUserAgent(httpRequest);
            String exhaustedUid = user.getId().toString();
            log.warn("AUDIT: 2FA OTP attempts exhausted — method: {}, userId={}, ip={}, userAgent={}",
                    method, exhaustedUid, clientIp, ua);
            auditLogPort.logTwoFactorFailed(exhaustedUid, method,
                    "otp_attempts_exhausted", clientIp, ua);
            throw e;
        } catch (Exception e) {
            String clientIp = getClientIP(httpRequest);
            String ua = getUserAgent(httpRequest);
            log.error("AUDIT: 2FA error — method: {}, userId={}, error: {}, ip={}, userAgent={}",
                    method, user.getId(), e.getMessage(), clientIp, ua);
            auditLogPort.logTwoFactorFailed(user.getId().toString(), method, "error: " + e.getMessage(), clientIp, ua);
            // P1 hygiene 2026-05-07: server-side error during verify is a
            // 500-class failure, not a successful response. Logging at ERROR
            // already; surface to clients as 500 so monitoring catches it.
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("success", false, "message", "Verification error: " + e.getMessage()));
        }
    }

    // ==================== N-STEP MFA FLOW (RFC 8176 compliant) ====================
    //
    // The bulk of {@code verifyMfaStep} (per-method dispatch, audit logging,
    // step accounting, JWT minting) was extracted to
    // {@link com.fivucsas.identity.application.service.mfa.VerifyMfaStepService}
    // in the P2.9 refactor (refactor/verify-mfa-step-extract). The controller
    // now only parses the request envelope and translates the service's
    // status hint into HTTP. The wire contract of POST /auth/mfa/step is
    // unchanged.

    @SuppressWarnings("unchecked")
    @PostMapping("/mfa/step")
    @Operation(summary = "Verify an MFA step (public — no JWT required, uses session token)")
    public ResponseEntity<Map<String, Object>> verifyMfaStep(
            @RequestBody Map<String, Object> request,
            HttpServletRequest httpRequest) {

        Map<String, Object> data = (Map<String, Object>) request.getOrDefault("data", Map.of());
        com.fivucsas.identity.application.service.mfa.VerifyMfaStepRequest serviceReq =
                new com.fivucsas.identity.application.service.mfa.VerifyMfaStepRequest(
                        (String) request.get("sessionToken"),
                        (String) request.get("method"),
                        data,
                        getClientIP(httpRequest),
                        getUserAgent(httpRequest));

        com.fivucsas.identity.application.service.mfa.VerifyMfaStepResponse result =
                verifyMfaStepService.execute(serviceReq);

        return switch (result.status()) {
            case OK -> ResponseEntity.ok(result.body());
            case BAD_REQUEST -> ResponseEntity.badRequest().body(result.body());
            case UNAUTHORIZED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result.body());
            case CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(result.body());
        };
    }


    /**
     * Cancel a half-complete MFA session. Post-audit 2026-04-24 login edge case #3.
     *
     * <p>Rationale: the hosted login UI needs a "never mind" button for users
     * trapped in a multi-step flow (e.g. lost their TOTP device mid-flow, or
     * realised they wanted a different account). Without this endpoint their
     * only recourse was to wait 10 minutes for {@code expiresAt} to pass.
     *
     * <p>Anonymous (pre-JWT) — the MFA session token itself is the
     * authentication: whoever holds it started the flow and may end it.
     * Rate-limited by the existing login bucket via {@link RateLimitInterceptor}
     * path match on {@code /auth/mfa/}.
     */
    @DeleteMapping("/mfa/session/{sessionToken}")
    @Operation(summary = "Cancel an in-flight MFA session (public — no JWT, uses session token)")
    public ResponseEntity<Void> cancelMfaSession(
            @PathVariable String sessionToken,
            HttpServletRequest httpRequest) {
        if (sessionToken == null || sessionToken.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        String clientIp = getClientIP(httpRequest);
        String ua = getUserAgent(httpRequest);

        // Rate limit using the login bucket so a stuck client cannot spam
        // cancel requests as a proxy for session discovery. Shares
        // bucket with /auth/login and /auth/mfa/step.
        if (!rateLimitService.allowLoginAttempt(clientIp)) {
            long retryAfter = rateLimitService.getSecondsUntilRefill(
                    clientIp, RateLimitService.RateLimitType.LOGIN);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header("Retry-After", String.valueOf(retryAfter))
                    .build();
        }

        Optional<MfaSession> sessionOpt = mfaSessionRepository.findBySessionToken(sessionToken);
        if (sessionOpt.isEmpty()) {
            // Do not leak whether the token was ever valid. 204 is safe: the
            // caller wanted the session gone, and it is gone.
            log.info("AUDIT: MFA session cancel — token not found (treated as success), ip={}, userAgent={}",
                    clientIp, ua);
            return ResponseEntity.noContent().build();
        }

        MfaSession session = sessionOpt.get();
        if (session.isCompleted()) {
            // A completed session has already minted its token elsewhere;
            // cancelling it is a no-op (the JWT is already in the wild).
            log.warn("AUDIT: MFA session cancel — session already completed, userId={}, ip={}, userAgent={}",
                    session.getUserId(), clientIp, ua);
            return ResponseEntity.noContent().build();
        }

        session.cancel();
        mfaSessionRepository.save(session);

        log.info("AUDIT: MFA session cancelled by user — userId={}, currentStep={}/{}, ip={}, userAgent={}",
                session.getUserId(), session.getCurrentStep(), session.getTotalSteps(), clientIp, ua);
        auditLogPort.logSecurityEvent(
                session.getUserId().toString(),
                "MFA_SESSION_CANCELLED",
                clientIp,
                "cancelled_by_user: step=" + session.getCurrentStep() + "/" + session.getTotalSteps()
        );

        return ResponseEntity.noContent()
                .header("X-Cancelled-By", "user")
                .build();
    }

    /**
     * Switch the current MFA step to use a different enrolled method, provided the
     * step's configuration allows it. Post-audit 2026-04-24 login edge case #6.
     *
     * <p>Typical use: user started a TOTP step but realised their authenticator
     * is on another device — switch to EMAIL_OTP (if the flow's step lists
     * EMAIL_OTP as an available/alternative method and the user has email
     * enrolled).
     *
     * <p>Request body: {@code {"sessionToken": "...", "method": "EMAIL_OTP"}}.
     * Response: {@code {"status":"METHOD_SWITCHED", "currentStep":N,
     * "expectedMethod":"EMAIL_OTP", "availableMethods":[...]}}.
     */
    @PostMapping("/mfa/switch-method")
    @Operation(summary = "Switch the current MFA step to an alternative method (public — no JWT, uses session token)")
    public ResponseEntity<Map<String, Object>> switchMfaMethod(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) {
        String sessionToken = request.get("sessionToken");
        String newMethod = request.get("method");

        if (sessionToken == null || sessionToken.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "ERROR", "message", "sessionToken is required"));
        }
        if (newMethod == null || newMethod.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "ERROR", "message", "method is required"));
        }

        String clientIp = getClientIP(httpRequest);
        String ua = getUserAgent(httpRequest);

        Optional<MfaSession> sessionOpt = mfaSessionRepository.findBySessionToken(sessionToken);
        if (sessionOpt.isEmpty() || sessionOpt.get().isExpired()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "status", "ERROR", "message", "Invalid or expired MFA session"));
        }
        MfaSession mfaSession = sessionOpt.get();
        if (mfaSession.isCompleted()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "ERROR", "message", "MFA session already completed"));
        }

        AuthMethodType requestedType;
        try {
            requestedType = AuthMethodType.valueOf(newMethod);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "ERROR", "message", "Unknown auth method: " + newMethod));
        }

        AuthFlow flow = authFlowRepository.findById(mfaSession.getFlowId()).orElse(null);
        if (flow == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "status", "ERROR", "message", "Auth flow not found for session"));
        }
        int currentStepOrder = mfaSession.getCurrentStep();
        AuthFlowStep currentStep = flow.getSteps().stream()
                .filter(s -> s.getStepOrder() == currentStepOrder)
                .findFirst()
                .orElse(null);
        if (currentStep == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "status", "ERROR", "message", "Current step " + currentStepOrder + " not found in flow"));
        }

        User user = userRepository.findById(mfaSession.getUserId())
                .orElseThrow(() -> new UserNotFoundException("User not found for MFA session"));

        // Permitted methods for this step: the explicit available set (CHOICE
        // steps) plus the configured fallback (SEQUENTIAL steps w/ fallback).
        java.util.Set<AuthMethodType> permitted = new java.util.HashSet<>();
        for (AuthMethod m : currentStep.getAvailableMethods()) {
            if (m != null && m.getType() != null) {
                permitted.add(m.getType());
            }
        }
        if (currentStep.getFallbackMethod() != null && currentStep.getFallbackMethod().getType() != null) {
            permitted.add(currentStep.getFallbackMethod().getType());
        }

        if (!permitted.contains(requestedType)) {
            log.warn("AUDIT: MFA switch-method rejected — method {} not permitted on step {}, userId={}, ip={}",
                    requestedType, currentStepOrder, user.getId(), clientIp);
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "status", "ERROR",
                    "error", "METHOD_NOT_PERMITTED",
                    "message", "Method " + requestedType + " is not an alternative for the current step",
                    "permittedMethods", permitted.stream().map(Enum::name).sorted().toList()
            ));
        }

        // Block substitution: user cannot switch to a method they've already
        // completed earlier in the flow unless that method is explicitly the
        // method configured for the current step (legitimate repetition).
        String requestedName = requestedType.name();
        java.util.Set<String> currentStepMethodNames = currentStep.getAvailableMethods().stream()
                .filter(java.util.Objects::nonNull)
                .map(m -> m.getType().name())
                .collect(java.util.stream.Collectors.toSet());
        if (mfaSession.getCompletedMethods().contains(requestedName)
                && !currentStepMethodNames.contains(requestedName)) {
            log.warn("AUDIT: MFA switch-method rejected — method {} already completed earlier, userId={}, ip={}",
                    requestedType, user.getId(), clientIp);
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "status", "ERROR",
                    "error", "METHOD_ALREADY_USED",
                    "message", "Method " + requestedType + " was already completed earlier in this flow"
            ));
        }

        // Verify the user is enrolled in the requested method. Otherwise switching
        // would just trap them again on a new method.
        Map<AuthMethodType, Boolean> healthStatus = enrollmentHealthService.validateEnrollments(user.getId());
        AuthMethod requestedMethod = currentStep.getAvailableMethods().stream()
                .filter(m -> m != null && m.getType() == requestedType)
                .findFirst()
                .orElse(currentStep.getFallbackMethod() != null
                        && currentStep.getFallbackMethod().getType() == requestedType
                        ? currentStep.getFallbackMethod() : null);
        boolean requiresEnrollment = requestedMethod == null || requestedMethod.isRequiresEnrollment();
        boolean isEnrolled = !requiresEnrollment || Boolean.TRUE.equals(healthStatus.get(requestedType));
        if (!isEnrolled) {
            String enrollmentPath = "/enroll/" + requestedType.name().toLowerCase(java.util.Locale.ROOT);
            log.warn("AUDIT: MFA switch-method blocked — user not enrolled for {}, userId={}, ip={}",
                    requestedType, user.getId(), clientIp);
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "status", "ERROR",
                    "error", "NEEDS_ENROLLMENT",
                    "method", requestedType.name(),
                    "enrollmentUrl", enrollmentPath,
                    "message", "You are not enrolled in " + requestedType + ". Please enroll first."
            ));
        }

        // Pre-send OTP for methods that require an async out-of-band delivery, so
        // the next /mfa/step POST can validate the code the user received.
        try {
            if (requestedType == AuthMethodType.EMAIL_OTP) {
                String code = otpService.generate(TWO_FA_OTP_PREFIX + user.getId());
                emailService.sendOtp(user.getEmail(), code);
            } else if (requestedType == AuthMethodType.SMS_OTP) {
                String phone = user.getPhoneNumber();
                if (phone != null && !phone.isBlank()) {
                    String code = otpService.generate("2fa-sms:" + user.getId());
                    smsService.sendOtp(phone, code);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to dispatch OTP for switched MFA method {} userId={}: {}",
                    requestedType, user.getId(), e.getMessage());
        }

        List<AvailableMfaMethod> availableMethods = buildMfaAvailableMethods(currentStep, user);

        log.info("AUDIT: MFA switch-method — userId={}, step={}, to={}, ip={}, userAgent={}",
                user.getId(), currentStepOrder, requestedType, clientIp, ua);
        auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "MFA_METHOD_SWITCHED",
                clientIp,
                "step=" + currentStepOrder + " newMethod=" + requestedType
        );

        return ResponseEntity.ok(Map.of(
                "status", "METHOD_SWITCHED",
                "mfaSessionToken", sessionToken,
                "currentStep", currentStepOrder,
                "totalSteps", mfaSession.getTotalSteps(),
                "expectedMethod", requestedType.name(),
                "availableMethods", availableMethods,
                "alternativeMethods", computeAlternativeMethods(currentStep, availableMethods, requestedType),
                "completedMethods", mfaSession.getCompletedMethods()
        ));
    }

    /** Build available methods for an MFA step, validated against actual backing data. */
    private List<AvailableMfaMethod> buildMfaAvailableMethods(AuthFlowStep step, User user) {
        return buildMfaAvailableMethods(step, user, java.util.Collections.emptySet());
    }

    /**
     * Build available methods for an MFA step, excluding any method already used
     * earlier in this MFA session. Without this filter, a 3-step CHOICE flow
     * where the same method appears in multiple steps (e.g. FINGERPRINT in both
     * step 2 and step 3) would re-offer the just-completed method as the next
     * step's primary, causing the same step to run twice.
     */
    private List<AvailableMfaMethod> buildMfaAvailableMethods(
            AuthFlowStep step, User user, java.util.Set<String> alreadyCompleted) {
        List<AuthMethod> methods = step.getAvailableMethods();
        Map<AuthMethodType, Boolean> healthStatus = enrollmentHealthService.validateEnrollments(user.getId());
        String preferred = user.getPreferred2faMethod();
        return methods.stream()
            .filter(Objects::nonNull)
            .filter(m -> !alreadyCompleted.contains(m.getType().name()))
            .map(m -> AvailableMfaMethod.builder()
                .methodType(m.getType().name())
                .name(m.getName())
                .category(m.getCategory().name())
                .enrolled(Boolean.TRUE.equals(healthStatus.get(m.getType())) || !m.isRequiresEnrollment())
                .preferred(m.getType().name().equals(preferred))
                .requiresEnrollment(m.isRequiresEnrollment())
                .build())
            .collect(java.util.stream.Collectors.toList());
    }

    /**
     * Returns the methods the user could switch to at the current step, minus
     * the one they're currently attempting. Used by {@code /mfa/switch-method}
     * and the enriched {@code /mfa/step} response.
     */
    private List<AvailableMfaMethod> computeAlternativeMethods(
            AuthFlowStep step, List<AvailableMfaMethod> available, AuthMethodType primary) {
        if (available == null || available.isEmpty()) {
            return List.of();
        }
        return available.stream()
                .filter(m -> !m.getMethodType().equals(primary.name()))
                .collect(java.util.stream.Collectors.toList());
    }

    @PostMapping("/mfa/qr-generate")
    @Operation(summary = "Generate QR token during MFA flow (public — no JWT, uses session token)")
    public ResponseEntity<Map<String, Object>> generateMfaQrToken(@RequestBody Map<String, String> request) {
        String sessionToken = request.get("sessionToken");
        if (sessionToken == null || sessionToken.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("message", "sessionToken is required"));
        }

        Optional<MfaSession> sessionOpt = mfaSessionRepository.findBySessionToken(sessionToken);
        if (sessionOpt.isEmpty() || sessionOpt.get().isExpired()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Invalid or expired MFA session"));
        }

        UUID userId = sessionOpt.get().getUserId();
        String token = qrCodeService.generateToken(userId);

        return ResponseEntity.ok(Map.of(
            "token", token,
            "expiresInSeconds", 300,
            "message", "Scan the QR code with the FIVUCSAS mobile app"
        ));
    }

    @PostMapping("/mfa/send-otp")
    @Operation(summary = "Send OTP during MFA flow (public — no JWT, uses session token)")
    public ResponseEntity<Map<String, String>> sendMfaOtp(@RequestBody Map<String, String> request) {
        String sessionToken = request.get("sessionToken");
        String method = request.getOrDefault("method", "EMAIL_OTP");

        if (sessionToken == null || sessionToken.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("message", "sessionToken is required"));
        }

        Optional<MfaSession> sessionOpt = mfaSessionRepository.findBySessionToken(sessionToken);
        if (sessionOpt.isEmpty() || sessionOpt.get().isExpired()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Invalid or expired MFA session"));
        }

        User user = userRepository.findById(sessionOpt.get().getUserId())
            .orElseThrow(() -> new UserNotFoundException("User not found"));

        if ("SMS_OTP".equals(method)) {
            String phone = user.getPhoneNumber();
            if (phone == null || phone.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("message", "No phone number on file"));
            }
            String code = otpService.generate("2fa-sms:" + user.getId());
            smsService.sendOtp(phone, code);
            String maskedPhone = phone.length() > 4 ? "***" + phone.substring(phone.length() - 4) : "***";
            return ResponseEntity.ok(Map.of("message", "SMS code sent", "phone", maskedPhone));
        } else {
            String code = otpService.generate(TWO_FA_OTP_PREFIX + user.getId());
            emailService.sendOtp(user.getEmail(), code);
            String email = user.getEmail();
            String maskedEmail = email.substring(0, Math.min(3, email.indexOf('@'))) + "***" + email.substring(email.indexOf('@'));
            return ResponseEntity.ok(Map.of("message", "Email code sent", "email", maskedEmail));
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
        if (response.isMfaRequired() && response.getMfaSessionToken() != null) {
            return AuthResponse.ofMfa(
                response.getAccessToken(),
                response.getRefreshToken(),
                response.getExpiresIn(),
                response.getUser(),
                response.getMfaSessionToken(),
                response.getTotalSteps(),
                response.getCurrentStep(),
                response.getTwoFactorMethod(),
                response.getAvailableMethods(),
                response.getCompletedMethods()
            );
        }
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
     * Resolves a human-readable failure reason based on the auth method and submitted data.
     * Used to produce actionable audit log entries for failed authentication attempts.
     */
    private String resolveFailureReason(AuthMethodType methodType, Map<String, Object> data) {
        return switch (methodType) {
            case PASSWORD -> "invalid_password";
            case EMAIL_OTP, SMS_OTP -> {
                String code = data != null ? (String) data.get("code") : null;
                yield (code == null || code.isBlank()) ? "missing_otp_code" : "invalid_or_expired_otp";
            }
            case TOTP -> {
                String code = data != null ? (String) data.get("code") : null;
                yield (code == null || code.isBlank()) ? "missing_totp_code" : "invalid_totp_code";
            }
            case FACE -> {
                String image = data != null ? (String) data.get("image") : null;
                yield (image == null || image.isBlank()) ? "missing_face_image" : "face_verification_failed";
            }
            case VOICE -> {
                String voiceData = data != null ? (String) data.get("voiceData") : null;
                yield (voiceData == null || voiceData.isBlank()) ? "missing_voice_data" : "voice_verification_failed";
            }
            case FINGERPRINT, HARDWARE_KEY -> {
                // P0 FIX (Investigation 2026-05-07 F1): the legacy /2fa/verify-method
                // route cannot verify WebAuthn assertions (no challenge handshake);
                // we now fail closed and steer callers to the canonical paths.
                yield "legacy_route_unsupported_use_webauthn_authenticate";
            }
            case QR_CODE -> {
                String token = data != null ? (String) data.get("token") : null;
                yield (token == null || token.isBlank()) ? "missing_qr_token" : "invalid_qr_token";
            }
            case NFC_DOCUMENT -> {
                String nfcData = data != null ? (String) data.get("nfcData") : null;
                yield (nfcData == null || nfcData.isBlank()) ? "missing_nfc_data" : "nfc_card_not_found_or_not_owned";
            }
            default -> "verification_failed";
        };
    }

    /**
     * Resolve TOTP secret: try Redis (cache) first, fall back to PostgreSQL (source of truth).
     * If found only in DB, re-cache in Redis for subsequent fast lookups.
     */
    private String resolveTotpSecret(User user) {
        String redisKey = "totp:secret:" + user.getId();
        String secret = redisTemplate.opsForValue().get(redisKey);
        if (secret == null && user.getTwoFactorSecret() != null) {
            // BE-H3: DB value may be enc:v1:... (encrypted) or legacy plaintext.
            // decryptIfNeeded() handles both; Redis cache always holds plaintext.
            secret = totpSecretCipher.decryptIfNeeded(user.getTwoFactorSecret());
            redisTemplate.opsForValue().set(redisKey, secret);
            log.info("TOTP secret re-cached in Redis for user: {}", user.getId());
        }
        return secret;
    }
}
