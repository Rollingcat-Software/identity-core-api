package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RevokeAllSessionsCommand;
import com.fivucsas.identity.application.port.input.RevokeAllSessionsUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Use case service for revoking all sessions except current.
 *
 * Implements the RevokeAllSessionsUseCase input port.
 * Useful for "Logout from all other devices" feature.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RevokeAllSessionsService implements RevokeAllSessionsUseCase {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditLogPort auditLogPort;

    @Override
    @Transactional
    public void execute(RevokeAllSessionsCommand command) {
        log.info("Revoke all sessions request for user: {}", command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + command.getEmail()));

        UUID currentTokenId = UUID.fromString(command.getCurrentTokenId());

        int revokedCount = refreshTokenRepository.revokeAllUserTokensExceptCurrent(
            user,
            currentTokenId,
            Instant.now()
        );

        log.info("Revoked {} sessions for user: {}", revokedCount, command.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "ALL_SESSIONS_REVOKED",
            command.getIpAddress(),
            String.format("Revoked %d sessions (kept current)", revokedCount)
        );
    }
}
