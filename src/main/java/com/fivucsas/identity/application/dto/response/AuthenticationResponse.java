package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response for authentication operations (login, register, refresh).
 *
 * Following principles:
 * - Single Responsibility: Only contains authentication response data
 * - Immutability: Use with @Builder for safer construction
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {

    private String accessToken;
    private String refreshToken;
    private Long expiresIn;
    private UserResponse user;
    private boolean twoFactorRequired;
    /** The auth method type required for the second factor (e.g. "TOTP", "FACE", "EMAIL_OTP"). Null when twoFactorRequired is false. */
    private String twoFactorMethod;

    public static AuthenticationResponse of(String accessToken, String refreshToken, Long expiresIn, UserResponse user) {
        return AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .expiresIn(expiresIn)
            .user(user)
            .twoFactorRequired(false)
            .twoFactorMethod(null)
            .build();
    }

    public static AuthenticationResponse of(String accessToken, String refreshToken, Long expiresIn, UserResponse user, boolean twoFactorRequired) {
        return AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .expiresIn(expiresIn)
            .user(user)
            .twoFactorRequired(twoFactorRequired)
            .twoFactorMethod(null)
            .build();
    }

    public static AuthenticationResponse of(String accessToken, String refreshToken, Long expiresIn, UserResponse user, boolean twoFactorRequired, String twoFactorMethod) {
        return AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .expiresIn(expiresIn)
            .user(user)
            .twoFactorRequired(twoFactorRequired)
            .twoFactorMethod(twoFactorMethod)
            .build();
    }
}
