package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RefreshTokenCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.RefreshTokenUseCase;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.TenantSuspendedException;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for refreshing access tokens.
 *
 * Implements the RefreshTokenUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshAccessTokenService implements RefreshTokenUseCase {

    private final RefreshTokenService refreshTokenService;
    private final TokenGenerationPort tokenGenerator;

    @Override
    @Transactional
    public AuthenticationResponse execute(RefreshTokenCommand command) {
        log.info("Refreshing token");

        RefreshToken refreshToken = refreshTokenService.findByToken(command.getRefreshToken());
        refreshTokenService.verifyExpiration(refreshToken);

        User user = refreshToken.getUser();

        // P0-#8 (INVESTIGATION_MASTER_2026-05-07): refuse to mint a new access
        // token when the user's tenant is no longer ACTIVE. Without this gate,
        // a session that was active when the tenant went SUSPENDED could be
        // kept alive indefinitely via refresh — every 15 minutes the
        // refresh-token rotation would issue a fresh access token, totally
        // bypassing the suspension at /auth/login.
        if (user.getTenant() != null
                && user.getTenant().getStatus() != TenantStatus.ACTIVE) {
            log.warn("Token refresh refused — tenant not active, userEmail={}, tenantId={}, tenantStatus={}",
                    user.getEmail(), user.getTenant().getId(), user.getTenant().getStatus());
            throw new TenantSuspendedException(user.getTenant().getStatus());
        }

        // Rotate refresh token for security
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(
            refreshToken,
            command.getIpAddress(),
            command.getUserAgent()
        );

        String accessToken = tokenGenerator.generateAccessToken(user.getEmail());
        UserResponse userResponse = com.fivucsas.identity.application.mapper.UserResponseMapper.toResponse(user);

        log.info("Token refreshed successfully for user: {}", user.getEmail());

        return AuthenticationResponse.of(accessToken, newRefreshToken.getToken(), tokenGenerator.getExpirationMillis(), userResponse);
    }
}
