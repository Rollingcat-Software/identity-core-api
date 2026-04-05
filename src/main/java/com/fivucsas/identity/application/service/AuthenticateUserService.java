package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.AuthenticateUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.service.RefreshTokenService;
import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.entity.OAuth2Client;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Use case service for user authentication.
 *
 * Implements the AuthenticateUserUseCase input port.
 * Enforces account lockout after consecutive failed login attempts.
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
    private final AuthFlowRepositoryPort authFlowRepository;
    private final OAuth2ClientRepositoryPort oAuth2ClientRepository;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);

    @Override
    @Transactional
    public AuthenticationResponse execute(AuthenticateUserCommand command) {
        log.info("Login attempt for user: {}", command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(InvalidCredentialsException::new);

        // Check if account is locked
        if (user.isLocked()) {
            if (user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
                // Lock period expired, auto-unlock
                user.resetFailedLoginAttempts();
                userRepository.save(user);
                log.info("Account auto-unlocked after lockout period for user: {}", command.getEmail());
            } else {
                log.warn("Login attempt on locked account: {}", command.getEmail());
                auditLogPort.logAuthenticationFailed(command.getEmail(), command.getIpAddress(), "Account locked");
                throw new InvalidCredentialsException("Account is temporarily locked due to too many failed login attempts. Please try again later.");
            }
        }

        if (!passwordEncoder.matches(command.getPassword(), user.getPasswordHash())) {
            // Increment failed attempts and potentially lock account
            user.incrementFailedLoginAttempts();
            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.lockAccount(LOCKOUT_DURATION);
                log.warn("Account locked after {} failed attempts for user: {}", MAX_FAILED_ATTEMPTS, command.getEmail());
                auditLogPort.logAuthenticationFailed(command.getEmail(), command.getIpAddress(),
                        "Account locked after " + MAX_FAILED_ATTEMPTS + " failed attempts");
            } else {
                auditLogPort.logAuthenticationFailed(command.getEmail(), command.getIpAddress(),
                        "Invalid password (attempt " + user.getFailedLoginAttempts() + "/" + MAX_FAILED_ATTEMPTS + ")");
            }
            userRepository.save(user);
            log.warn("Invalid password for user: {}", command.getEmail());
            throw new InvalidCredentialsException();
        }

        // Successful login — reset failed attempts and record login metadata
        if (user.getFailedLoginAttempts() > 0) {
            user.resetFailedLoginAttempts();
        }
        user.recordLogin(command.getIpAddress());

        log.info("User logged in successfully: {}", user.getId());

        // Look up OAuth client name if login came from a widget/OAuth flow
        String oauthClientName = null;
        if (command.getClientId() != null && !command.getClientId().isBlank()) {
            try {
                Optional<OAuth2Client> oauthClient = oAuth2ClientRepository.findByClientId(command.getClientId());
                oauthClientName = oauthClient.map(OAuth2Client::getClientName).orElse(null);
            } catch (Exception e) {
                log.warn("Failed to look up OAuth client '{}': {}", command.getClientId(), e.getMessage());
            }
        }

        if (oauthClientName != null) {
            auditLogPort.logUserAuthenticated(user.getId().toString(), user.getEmail(), command.getIpAddress(), oauthClientName);
        } else {
            auditLogPort.logUserAuthenticated(user.getId().toString(), user.getEmail(), command.getIpAddress());
        }
        eventPublisher.publishUserAuthenticated(user.getId().toString(), user.getEmail());

        String accessToken = tokenGenerator.generateAccessToken(user.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(
            user,
            command.getIpAddress(),
            command.getUserAgent()
        );

        // Save user (resets failed attempts + updates lastLoginAt if needed)
        userRepository.save(user);

        // Check if tenant's default APP_LOGIN auth flow has more than 1 step (i.e. 2FA required)
        boolean twoFactorRequired = false;
        String twoFactorMethod = null;
        try {
            Optional<AuthFlow> defaultLoginFlow = authFlowRepository
                .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                    user.getTenant().getId(), OperationType.APP_LOGIN);
            if (defaultLoginFlow.isPresent()) {
                AuthFlow flow = defaultLoginFlow.get();
                if (flow.getStepCount() > 1) {
                    twoFactorRequired = true;
                    // Extract the method type from the second step (stepOrder=2)
                    twoFactorMethod = flow.getSteps().stream()
                        .filter(step -> step.getStepOrder() == 2)
                        .findFirst()
                        .map(step -> step.getAuthMethod().getType().name())
                        .orElse("EMAIL_OTP");
                }
            }
        } catch (Exception e) {
            log.warn("Failed to check tenant auth flow for user {}: {}", user.getId(), e.getMessage());
        }

        if (twoFactorRequired) {
            log.info("2FA required by tenant auth flow for user: {} (method: {})", user.getId(), twoFactorMethod);
        }

        UserResponse userResponse = com.fivucsas.identity.application.mapper.UserResponseMapper.toResponse(user);

        return AuthenticationResponse.of(accessToken, refreshToken.getToken(), tokenGenerator.getExpirationMillis(), userResponse, twoFactorRequired, twoFactorMethod);
    }
}
