package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.RegisterUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.model.user.Email;
import com.fivucsas.identity.domain.model.user.FullName;
import com.fivucsas.identity.domain.model.user.HashedPassword;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for user registration.
 *
 * Implements the RegisterUserUseCase input port.
 * This is the application layer coordinating the registration flow.
 *
 * Following principles:
 * - Single Responsibility: Only handles user registration logic
 * - Dependency Inversion: Depends on ports (interfaces), not implementations
 * - Open/Closed: New features added via new services
 * - Hexagonal Architecture: Application service coordinates domain and infrastructure
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterUserService implements RegisterUserUseCase {

    private final com.fivucsas.identity.domain.repository.UserRepository userRepository;
    private final JpaTenantRepository tenantRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogPort auditLogPort;
    private final com.fivucsas.identity.application.port.output.EventPublisherPort eventPublisher;
    private final com.fivucsas.identity.infrastructure.otp.OtpService otpService;
    private final com.fivucsas.identity.infrastructure.email.EmailService emailService;

    @Value("${app.default-tenant-slug:default}")
    private String defaultTenantSlug;

    @Override
    @Transactional
    public AuthenticationResponse execute(RegisterUserCommand command) {
        log.info("Registering new user: {}", command.getEmail());

        // Validate email uniqueness
        if (userRepository.existsByEmail(command.getEmail())) {
            throw new DuplicateEmailException(command.getEmail());
        }

        // Validate inputs using value objects
        Email email = Email.of(command.getEmail());
        FullName fullName = FullName.of(command.getFirstName(), command.getLastName());

        // Hash password
        String hashedPasswordString = passwordEncoder.encode(command.getPassword());
        HashedPassword hashedPassword = HashedPassword.of(hashedPasswordString);

        // Resolve tenant from request context (TenantContext), fallback to default
        Tenant defaultTenant;
        java.util.UUID contextTenantId = com.fivucsas.identity.infrastructure.multitenancy.TenantContext.getCurrentTenant();
        if (contextTenantId != null) {
            defaultTenant = tenantRepository.findById(contextTenantId)
                .orElseThrow(() -> new com.fivucsas.identity.domain.exception.TenantNotFoundException(contextTenantId.toString()));
        } else {
            defaultTenant = tenantRepository.findBySlug(defaultTenantSlug)
                .orElseGet(() -> tenantRepository.findAll().stream().findFirst()
                    .orElseThrow(() -> new IllegalStateException("No tenant found in the system")));
            log.warn("No tenant context set during registration, falling back to default tenant: {}", defaultTenant.getSlug());
        }

        // Create user entity
        User user = User.builder()
            .email(email.getValue())
            .passwordHash(hashedPassword.getValue())
            .firstName(fullName.getFirstName())
            .lastName(fullName.getLastName())
            .tenant(defaultTenant)
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .build();

        // Save user
        User savedUser = userRepository.save(user);
        log.info("User registered successfully: {}", savedUser.getId());
        auditLogPort.logUserRegistered(savedUser.getId().toString(), savedUser.getEmail(), command.getIpAddress());
        eventPublisher.publishUserRegistered(savedUser.getId().toString(), savedUser.getEmail());

        // Send email verification code
        try {
            String verificationCode = otpService.generate("email-verify:" + savedUser.getId());
            emailService.sendOtp(savedUser.getEmail(), verificationCode);
            log.info("Email verification code sent to: {}", savedUser.getEmail());
        } catch (Exception e) {
            log.warn("Failed to send email verification code to: {}", savedUser.getEmail(), e);
        }

        // Generate tokens
        String accessToken = tokenGenerator.generateAccessToken(savedUser.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
            savedUser,
            command.getIpAddress(),
            command.getUserAgent()
        );

        // Map to response
        UserResponse userResponse = com.fivucsas.identity.application.mapper.UserResponseMapper.toResponse(savedUser);

        return AuthenticationResponse.of(accessToken, refreshToken.getToken(), tokenGenerator.getExpirationMillis(), userResponse);
    }
}
