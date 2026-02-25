package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.LogoutCommand;
import com.fivucsas.identity.application.port.input.LogoutUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for user logout.
 *
 * Implements the LogoutUserUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class LogoutUserService implements LogoutUserUseCase {

    private final RefreshTokenService refreshTokenService;
    private final AuditLogPort auditLogPort;

    @Override
    @Transactional
    public void execute(LogoutCommand command) {
        log.info("Logout request for user: {}", command.getCurrentUserEmail());

        try {
            RefreshToken token = refreshTokenService.findByToken(command.getRefreshToken());
            String userId = token.getUser().getId().toString();
            String email = token.getUser().getEmail();

            // Validate token ownership - prevent revoking another user's token
            if (command.getCurrentUserEmail() != null && !email.equals(command.getCurrentUserEmail())) {
                log.warn("User {} attempted to revoke token belonging to {}", command.getCurrentUserEmail(), email);
                throw new com.fivucsas.identity.domain.exception.UnauthorizedException("Cannot revoke another user's token");
            }

            refreshTokenService.revokeToken(command.getRefreshToken());
            log.info("Logout successful for user: {}", email);

            auditLogPort.logUserLoggedOut(userId, email);
        } catch (com.fivucsas.identity.domain.exception.UnauthorizedException e) {
            throw e; // Re-throw authorization errors
        } catch (Exception e) {
            log.warn("Logout attempted with invalid token: {}", e.getMessage());
            // Don't throw exception - logout should be idempotent
        }
    }
}
