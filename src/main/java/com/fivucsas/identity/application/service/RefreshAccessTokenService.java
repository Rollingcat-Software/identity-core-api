package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RefreshTokenCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.RefreshTokenUseCase;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.entity.RefreshToken;
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

        // Rotate refresh token for security
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(
            refreshToken,
            command.getIpAddress(),
            command.getUserAgent()
        );

        String accessToken = tokenGenerator.generateAccessToken(user.getEmail());
        UserResponse userResponse = mapToUserResponse(user);

        log.info("Token refreshed successfully for user: {}", user.getEmail());

        return AuthenticationResponse.of(accessToken, newRefreshToken.getToken(), userResponse);
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
