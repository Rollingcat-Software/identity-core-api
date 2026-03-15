package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RevokeSessionCommand;
import com.fivucsas.identity.application.port.input.RevokeSessionUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.ResourceNotFoundException;
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
 * Use case service for revoking a specific session.
 *
 * Implements the RevokeSessionUseCase input port.
 * Used by the "Logout from this device" feature.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RevokeSessionService implements RevokeSessionUseCase {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditLogPort auditLogPort;

    @Override
    @Transactional
    public void execute(RevokeSessionCommand command) {
        log.info("Revoke session {} for user: {}", command.getSessionId(), command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + command.getEmail()));

        UUID tokenId = UUID.fromString(command.getSessionId());

        int revokedCount = refreshTokenRepository.revokeUserToken(user, tokenId, Instant.now());

        if (revokedCount == 0) {
            throw new ResourceNotFoundException("Session", command.getSessionId());
        }

        log.info("Session {} revoked for user: {}", command.getSessionId(), command.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "SESSION_REVOKED",
            command.getIpAddress(),
            "Session revoked: " + command.getSessionId()
        );
    }
}
