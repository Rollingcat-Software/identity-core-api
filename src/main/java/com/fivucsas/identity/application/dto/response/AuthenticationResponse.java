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
    private UserResponse user;

    public static AuthenticationResponse of(String accessToken, String refreshToken, UserResponse user) {
        return AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .user(user)
            .build();
    }
}
