package com.fivucsas.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private String accessToken;
    private String tokenType;
    private UserDto user;

    public static AuthResponse of(String token, UserDto user) {
        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .user(user)
                .build();
    }
}
