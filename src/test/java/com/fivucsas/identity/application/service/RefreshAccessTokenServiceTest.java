package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RefreshTokenCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.TenantSuspendedException;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshAccessTokenService Tests")
class RefreshAccessTokenServiceTest {

    // Valid BCrypt hash for testing
    private static final String VALID_BCRYPT_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private TokenGenerationPort tokenGenerator;

    @InjectMocks
    private RefreshAccessTokenService refreshAccessTokenService;

    private RefreshTokenCommand validCommand;
    private User user;
    private RefreshToken existingToken;
    private RefreshToken newToken;

    @BeforeEach
    void setUp() {
        validCommand = RefreshTokenCommand.builder()
            .refreshToken("existing-refresh-token")
            .ipAddress("192.168.1.1")
            .userAgent("Mozilla/5.0")
            .build();

        user = User.builder()
            .id(UUID.randomUUID())
            .email("test@example.com")
            .passwordHash(VALID_BCRYPT_HASH)
            .firstName("John")
            .lastName("Doe")
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();

        existingToken = RefreshToken.builder()
            .id(UUID.randomUUID())
            .token("existing-refresh-token")
            .user(user)
            .expiryDate(Instant.now().plus(Duration.ofDays(7)))
            .build();

        newToken = RefreshToken.builder()
            .id(UUID.randomUUID())
            .token("new-refresh-token")
            .user(user)
            .expiryDate(Instant.now().plus(Duration.ofDays(7)))
            .build();
    }

    @Nested
    @DisplayName("Successful Token Refresh")
    class SuccessfulTokenRefresh {

        @Test
        @DisplayName("Should refresh token successfully")
        void shouldRefreshTokenSuccessfully() {
            // Given
            when(refreshTokenService.findByToken("existing-refresh-token")).thenReturn(existingToken);
            when(refreshTokenService.verifyExpiration(existingToken)).thenReturn(existingToken);
            when(refreshTokenService.rotateRefreshToken(eq(existingToken), eq("192.168.1.1"), eq("Mozilla/5.0")))
                .thenReturn(newToken);
            when(tokenGenerator.generateAccessToken("test@example.com")).thenReturn("new-access-token");

            // When
            AuthenticationResponse response = refreshAccessTokenService.execute(validCommand);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo("new-access-token");
            assertThat(response.getRefreshToken()).isEqualTo("new-refresh-token");
            assertThat(response.getUser()).isNotNull();
            assertThat(response.getUser().getEmail()).isEqualTo("test@example.com");

            verify(refreshTokenService).findByToken("existing-refresh-token");
            verify(refreshTokenService).verifyExpiration(existingToken);
            verify(refreshTokenService).rotateRefreshToken(existingToken, "192.168.1.1", "Mozilla/5.0");
            verify(tokenGenerator).generateAccessToken("test@example.com");
        }

        @Test
        @DisplayName("Should return complete user response")
        void shouldReturnCompleteUserResponse() {
            // Given
            User userWithDetails = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John")
                .lastName("Doe")
                .phoneNumber("+1234567890")
                .address("123 Main St")
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(true)
                .verificationCount(10)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            RefreshToken tokenWithUser = RefreshToken.builder()
                .id(UUID.randomUUID())
                .token("existing-refresh-token")
                .user(userWithDetails)
                .expiryDate(Instant.now().plus(Duration.ofDays(7)))
                .build();

            when(refreshTokenService.findByToken("existing-refresh-token")).thenReturn(tokenWithUser);
            when(refreshTokenService.verifyExpiration(tokenWithUser)).thenReturn(tokenWithUser);
            when(refreshTokenService.rotateRefreshToken(any(), any(), any())).thenReturn(newToken);
            when(tokenGenerator.generateAccessToken("test@example.com")).thenReturn("new-access-token");

            // When
            AuthenticationResponse response = refreshAccessTokenService.execute(validCommand);

            // Then
            assertThat(response.getUser().getFirstName()).isEqualTo("John");
            assertThat(response.getUser().getLastName()).isEqualTo("Doe");
            assertThat(response.getUser().getPhoneNumber()).isEqualTo("+1234567890");
            assertThat(response.getUser().getAddress()).isEqualTo("123 Main St");
            assertThat(response.getUser().isBiometricEnrolled()).isTrue();
            assertThat(response.getUser().getVerificationCount()).isEqualTo(10);
        }
    }

    @Nested
    @DisplayName("Token Refresh Failures")
    class TokenRefreshFailures {

        @Test
        @DisplayName("Should throw exception when token not found")
        void shouldThrowExceptionWhenTokenNotFound() {
            // Given
            when(refreshTokenService.findByToken("existing-refresh-token"))
                .thenThrow(new RuntimeException("Token not found"));

            // When/Then
            assertThatThrownBy(() -> refreshAccessTokenService.execute(validCommand))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Token not found");

            verify(refreshTokenService, never()).rotateRefreshToken(any(), any(), any());
            verify(tokenGenerator, never()).generateAccessToken(any());
        }

        @Test
        @DisplayName("Should throw exception when token is expired")
        void shouldThrowExceptionWhenTokenExpired() {
            // Given
            when(refreshTokenService.findByToken("existing-refresh-token")).thenReturn(existingToken);
            doThrow(new RuntimeException("Token expired"))
                .when(refreshTokenService).verifyExpiration(existingToken);

            // When/Then
            assertThatThrownBy(() -> refreshAccessTokenService.execute(validCommand))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Token expired");

            verify(refreshTokenService, never()).rotateRefreshToken(any(), any(), any());
            verify(tokenGenerator, never()).generateAccessToken(any());
        }
    }

    /**
     * P0-#8 (INVESTIGATION_MASTER_2026-05-07): block refresh-token rotation
     * for users whose tenant is no longer ACTIVE. Without this gate a session
     * that was alive when the tenant went SUSPENDED could be kept fresh
     * indefinitely via {@code /auth/refresh} — totally bypassing the
     * suspension at {@code /auth/login}.
     */
    @Nested
    @DisplayName("Tenant Suspension on refresh (P0-#8)")
    class TenantSuspendedOnRefresh {

        @Test
        @DisplayName("Should throw TenantSuspendedException when user.tenant.status != ACTIVE")
        void shouldThrowWhenTenantSuspended() {
            // Given — refresh token belongs to a user whose tenant is SUSPENDED.
            Tenant suspendedTenant = Tenant.builder()
                    .id(UUID.randomUUID())
                    .name("Suspended Tenant")
                    .status(TenantStatus.SUSPENDED)
                    .build();
            User suspendedTenantUser = User.builder()
                    .id(UUID.randomUUID())
                    .email("test@example.com")
                    .passwordHash(VALID_BCRYPT_HASH)
                    .firstName("John")
                    .lastName("Doe")
                    .status(UserStatus.ACTIVE)
                    .tenant(suspendedTenant)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();
            RefreshToken suspendedTenantToken = RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .token("existing-refresh-token")
                    .user(suspendedTenantUser)
                    .expiryDate(Instant.now().plus(Duration.ofDays(7)))
                    .build();

            when(refreshTokenService.findByToken("existing-refresh-token"))
                    .thenReturn(suspendedTenantToken);
            when(refreshTokenService.verifyExpiration(suspendedTenantToken))
                    .thenReturn(suspendedTenantToken);

            // When/Then
            assertThatThrownBy(() -> refreshAccessTokenService.execute(validCommand))
                    .isInstanceOf(TenantSuspendedException.class)
                    .satisfies(ex -> {
                        TenantSuspendedException tse = (TenantSuspendedException) ex;
                        assertThat(tse.getStatus()).isEqualTo(TenantStatus.SUSPENDED);
                        assertThat(tse.getErrorCode()).isEqualTo("TENANT_SUSPENDED");
                    });

            // Critical: refresh token MUST NOT be rotated (rotation issues a
            // new token; if we rotate before the gate, the old token is
            // already invalidated and the user is in a half-state). No new
            // access token must be minted.
            verify(refreshTokenService, never()).rotateRefreshToken(any(), any(), any());
            verify(tokenGenerator, never()).generateAccessToken(any());
            verify(tokenGenerator, never()).generateAccessToken(any(), any());
        }

        @Test
        @DisplayName("Should refresh successfully when tenant is ACTIVE")
        void shouldRefreshWhenTenantActive() {
            // Given — user tenant is ACTIVE.
            Tenant activeTenant = Tenant.builder()
                    .id(UUID.randomUUID())
                    .name("Active Tenant")
                    .status(TenantStatus.ACTIVE)
                    .build();
            User activeUser = User.builder()
                    .id(UUID.randomUUID())
                    .email("test@example.com")
                    .passwordHash(VALID_BCRYPT_HASH)
                    .firstName("John")
                    .lastName("Doe")
                    .status(UserStatus.ACTIVE)
                    .tenant(activeTenant)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();
            RefreshToken activeTenantToken = RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .token("existing-refresh-token")
                    .user(activeUser)
                    .expiryDate(Instant.now().plus(Duration.ofDays(7)))
                    .build();

            when(refreshTokenService.findByToken("existing-refresh-token"))
                    .thenReturn(activeTenantToken);
            when(refreshTokenService.verifyExpiration(activeTenantToken))
                    .thenReturn(activeTenantToken);
            when(refreshTokenService.rotateRefreshToken(eq(activeTenantToken), any(), any()))
                    .thenReturn(newToken);
            when(tokenGenerator.generateAccessToken("test@example.com")).thenReturn("new-access-token");

            // When
            AuthenticationResponse response = refreshAccessTokenService.execute(validCommand);

            // Then
            assertThat(response.getAccessToken()).isEqualTo("new-access-token");
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle null IP address and user agent")
        void shouldHandleNullIpAddressAndUserAgent() {
            // Given
            RefreshTokenCommand commandWithNulls = RefreshTokenCommand.builder()
                .refreshToken("existing-refresh-token")
                .ipAddress(null)
                .userAgent(null)
                .build();

            when(refreshTokenService.findByToken("existing-refresh-token")).thenReturn(existingToken);
            when(refreshTokenService.verifyExpiration(existingToken)).thenReturn(existingToken);
            when(refreshTokenService.rotateRefreshToken(eq(existingToken), isNull(), isNull()))
                .thenReturn(newToken);
            when(tokenGenerator.generateAccessToken("test@example.com")).thenReturn("new-access-token");

            // When
            AuthenticationResponse response = refreshAccessTokenService.execute(commandWithNulls);

            // Then
            assertThat(response).isNotNull();
            verify(refreshTokenService).rotateRefreshToken(existingToken, null, null);
        }
    }
}
