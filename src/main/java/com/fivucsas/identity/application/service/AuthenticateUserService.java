package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.AuthenticateUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for user authentication.
 *
 * Implements the AuthenticateUserUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticateUserService implements AuthenticateUserUseCase {

    private final com.fivucsas.identity.repository.UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogPort auditLogPort;

    @Override
    @Transactional
    public AuthenticationResponse execute(AuthenticateUserCommand command) {
        log.info("Login attempt for user: {}", command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(command.getPassword(), user.getPasswordHash())) {
            log.warn("Invalid password for user: {}", command.getEmail());
            auditLogPort.logAuthenticationFailed(command.getEmail(), command.getIpAddress(), "Invalid password");
            throw new InvalidCredentialsException();
        }

        log.info("User logged in successfully: {}", user.getId());
        auditLogPort.logUserAuthenticated(user.getId().toString(), user.getEmail(), command.getIpAddress());

        String accessToken = tokenGenerator.generateAccessToken(user.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
            user,
            command.getIpAddress(),
            command.getUserAgent()
        );

        UserResponse userResponse = mapToUserResponse(user);

        return AuthenticationResponse.of(accessToken, refreshToken.getToken(), tokenGenerator.getExpirationMillis(), userResponse);
    }

    private UserResponse mapToUserResponse(User user) {
        var roleNames = user.getRoleNames();
        return UserResponse.builder()
            .id(user.getId().toString())
            .email(user.getEmail())
            .firstName(user.getFirstName())
            .lastName(user.getLastName())
            .phoneNumber(user.getPhoneNumber())
            .address(user.getAddress())
            .idNumber(user.getIdNumber() != null ? user.getIdNumberAsValueObject().getMasked() : null)
            .status(user.getStatus().name())
            .role(roleNames.isEmpty() ? "USER" : roleNames.iterator().next())
            .roles(roleNames.isEmpty() ? java.util.Set.of("USER") : roleNames)
            .tenantId(user.getTenant() != null ? user.getTenant().getId().toString() : null)
            .isBiometricEnrolled(user.isBiometricEnrolled())
            .enrolledAt(user.getEnrolledAt())
            .lastVerifiedAt(user.getLastVerifiedAt())
            .verificationCount(user.getVerificationCount())
            .createdAt(user.getCreatedAt())
            .updatedAt(user.getUpdatedAt())
            .build();
    }
}
