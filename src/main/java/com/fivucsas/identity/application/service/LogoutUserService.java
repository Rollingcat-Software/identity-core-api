package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.LogoutCommand;
import com.fivucsas.identity.application.port.input.LogoutUserUseCase;
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

    @Override
    @Transactional
    public void execute(LogoutCommand command) {
        log.info("Logout request");

        try {
            refreshTokenService.revokeToken(command.getRefreshToken());
            log.info("Logout successful");
        } catch (Exception e) {
            log.warn("Logout attempted with invalid token: {}", e.getMessage());
            // Don't throw exception - logout should be idempotent
        }
    }
}
