package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.LogoutCommand;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("LogoutUserService Tests")
class LogoutUserServiceTest {

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private LogoutUserService logoutUserService;

    @Nested
    @DisplayName("Successful Logout")
    class SuccessfulLogout {

        @Test
        @DisplayName("Should logout successfully by revoking token")
        void shouldLogoutSuccessfully() {
            // Given
            LogoutCommand command = LogoutCommand.builder()
                .refreshToken("valid-refresh-token")
                .build();

            doNothing().when(refreshTokenService).revokeToken("valid-refresh-token");

            // When
            logoutUserService.execute(command);

            // Then
            verify(refreshTokenService).revokeToken("valid-refresh-token");
        }
    }

    @Nested
    @DisplayName("Logout with Invalid Token")
    class LogoutWithInvalidToken {

        @Test
        @DisplayName("Should not throw exception when token is invalid (idempotent)")
        void shouldNotThrowExceptionWhenTokenIsInvalid() {
            // Given
            LogoutCommand command = LogoutCommand.builder()
                .refreshToken("invalid-refresh-token")
                .build();

            doThrow(new RuntimeException("Token not found"))
                .when(refreshTokenService).revokeToken("invalid-refresh-token");

            // When/Then - Should not throw
            logoutUserService.execute(command);

            verify(refreshTokenService).revokeToken("invalid-refresh-token");
        }

        @Test
        @DisplayName("Should not throw exception when token is already revoked")
        void shouldNotThrowExceptionWhenTokenAlreadyRevoked() {
            // Given
            LogoutCommand command = LogoutCommand.builder()
                .refreshToken("revoked-refresh-token")
                .build();

            doThrow(new RuntimeException("Token already revoked"))
                .when(refreshTokenService).revokeToken("revoked-refresh-token");

            // When/Then - Should not throw
            logoutUserService.execute(command);

            verify(refreshTokenService).revokeToken("revoked-refresh-token");
        }

        @Test
        @DisplayName("Should not throw exception when token is expired")
        void shouldNotThrowExceptionWhenTokenExpired() {
            // Given
            LogoutCommand command = LogoutCommand.builder()
                .refreshToken("expired-refresh-token")
                .build();

            doThrow(new RuntimeException("Token expired"))
                .when(refreshTokenService).revokeToken("expired-refresh-token");

            // When/Then - Should not throw
            logoutUserService.execute(command);

            verify(refreshTokenService).revokeToken("expired-refresh-token");
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle empty token string")
        void shouldHandleEmptyTokenString() {
            // Given
            LogoutCommand command = LogoutCommand.builder()
                .refreshToken("")
                .build();

            doThrow(new RuntimeException("Empty token"))
                .when(refreshTokenService).revokeToken("");

            // When/Then - Should not throw (idempotent)
            logoutUserService.execute(command);

            verify(refreshTokenService).revokeToken("");
        }
    }
}
