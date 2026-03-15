package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.LogoutCommand;
import com.fivucsas.identity.application.port.input.LogoutUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.security.JwtService;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

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
    private final CachePort cachePort;
    private final JwtService jwtService;

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

            // Blacklist the access token JTI so it cannot be reused until expiry
            if (command.getAccessToken() != null) {
                String jti = jwtService.extractJti(command.getAccessToken());
                if (jti == null) {
                    log.error("Access token has no JTI claim — cannot blacklist");
                    throw new IllegalStateException("Access token missing JTI claim, cannot guarantee revocation");
                }
                long remainingMs = jwtService.extractExpiration(command.getAccessToken()).getTime() - System.currentTimeMillis();
                if (remainingMs > 0) {
                    cachePort.put("blacklist:" + jti, "1", Duration.ofMillis(remainingMs));
                    log.info("Access token JTI {} blacklisted (TTL {}ms)", jti, remainingMs);
                } else {
                    log.debug("Access token already expired, no need to blacklist");
                }
            } else {
                log.warn("Logout without access token — token cannot be blacklisted");
            }

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
