package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.RegisterUserUseCase;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.model.user.Email;
import com.fivucsas.identity.domain.model.user.FullName;
import com.fivucsas.identity.domain.model.user.HashedPassword;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    private final TenantRepository tenantRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;  // TODO: Convert to port

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

        // Get default tenant (TODO: In production, get from request context or subdomain)
        Tenant defaultTenant = tenantRepository.findBySlug("test-tenant")
            .orElseGet(() -> tenantRepository.findAll().stream().findFirst()
                .orElseThrow(() -> new IllegalStateException("No tenant found in the system")));

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

        // Generate tokens
        String accessToken = tokenGenerator.generateAccessToken(savedUser.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
            savedUser,
            command.getIpAddress(),
            command.getUserAgent()
        );

        // Map to response
        UserResponse userResponse = mapToUserResponse(savedUser);

        return AuthenticationResponse.of(accessToken, refreshToken.getToken(), userResponse);
    }

    private UserResponse mapToUserResponse(User user) {
        return UserResponse.builder()
            .id(user.getId().toString())
            .email(user.getEmail())
            .firstName(user.getFirstName())
            .lastName(user.getLastName())
            .phoneNumber(user.getPhoneNumber())
            .address(user.getAddress())
            .idNumber(user.getIdNumber() != null ? user.getIdNumberAsValueObject().getMasked() : null)
            .status(user.getStatus().name())
            .isBiometricEnrolled(user.isBiometricEnrolled())
            .enrolledAt(user.getEnrolledAt())
            .lastVerifiedAt(user.getLastVerifiedAt())
            .verificationCount(user.getVerificationCount())
            .createdAt(user.getCreatedAt())
            .updatedAt(user.getUpdatedAt())
            .build();
    }
}
