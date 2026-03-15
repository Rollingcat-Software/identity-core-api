package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.AuthenticateUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.repository.UserRepository;
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

    private final UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogPort auditLogPort;
    private final com.fivucsas.identity.application.port.output.EventPublisherPort eventPublisher;

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
        eventPublisher.publishUserAuthenticated(user.getId().toString(), user.getEmail());

        String accessToken = tokenGenerator.generateAccessToken(user.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
            user,
            command.getIpAddress(),
            command.getUserAgent()
        );

        UserResponse userResponse = com.fivucsas.identity.application.mapper.UserResponseMapper.toResponse(user);

        return AuthenticationResponse.of(accessToken, refreshToken.getToken(), tokenGenerator.getExpirationMillis(), userResponse);
    }
}
