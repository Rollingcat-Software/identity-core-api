package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.LogoutCommand;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("LogoutUserService Tests")
class LogoutUserServiceTest {

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private AuditLogPort auditLogPort;

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

            User mockUser = mock(User.class);
            when(mockUser.getId()).thenReturn(UUID.randomUUID());
            when(mockUser.getEmail()).thenReturn("test@example.com");

            RefreshToken mockToken = mock(RefreshToken.class);
            when(mockToken.getUser()).thenReturn(mockUser);

            when(refreshTokenService.findByToken("valid-refresh-token")).thenReturn(mockToken);
            doNothing().when(refreshTokenService).revokeToken("valid-refresh-token");

            // When
            logoutUserService.execute(command);

            // Then
            verify(refreshTokenService).findByToken("valid-refresh-token");
            verify(refreshTokenService).revokeToken("valid-refresh-token");
            verify(auditLogPort).logUserLoggedOut(anyString(), eq("test@example.com"));
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

            when(refreshTokenService.findByToken("invalid-refresh-token"))
                .thenThrow(new RuntimeException("Token not found"));

            // When/Then - Should not throw (caught by try/catch in service)
            logoutUserService.execute(command);

            verify(refreshTokenService).findByToken("invalid-refresh-token");
        }

        @Test
        @DisplayName("Should not throw exception when token is already revoked")
        void shouldNotThrowExceptionWhenTokenAlreadyRevoked() {
            // Given
            LogoutCommand command = LogoutCommand.builder()
                .refreshToken("revoked-refresh-token")
                .build();

            when(refreshTokenService.findByToken("revoked-refresh-token"))
                .thenThrow(new RuntimeException("Token already revoked"));

            // When/Then - Should not throw
            logoutUserService.execute(command);

            verify(refreshTokenService).findByToken("revoked-refresh-token");
        }

        @Test
        @DisplayName("Should not throw exception when token is expired")
        void shouldNotThrowExceptionWhenTokenExpired() {
            // Given
            LogoutCommand command = LogoutCommand.builder()
                .refreshToken("expired-refresh-token")
                .build();

            when(refreshTokenService.findByToken("expired-refresh-token"))
                .thenThrow(new RuntimeException("Token expired"));

            // When/Then - Should not throw
            logoutUserService.execute(command);

            verify(refreshTokenService).findByToken("expired-refresh-token");
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

            when(refreshTokenService.findByToken(""))
                .thenThrow(new RuntimeException("Empty token"));

            // When/Then - Should not throw (idempotent)
            logoutUserService.execute(command);

            verify(refreshTokenService).findByToken("");
        }
    }
}
