package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.EventPublisherPort;
import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * P0 regression test for the MFA fail-OPEN bug
 * (BACKEND_REVIEW_2026-04-30 §7, ENGINEERING_REVIEW §3).
 *
 * <p>Pre-fix, {@link AuthenticateUserService#execute(AuthenticateUserCommand)}
 * wrapped the MFA-flow lookup in a blanket {@code catch (Exception)} that
 * log-and-continued. ANY non-DB exception (NPE, IllegalState, lazy-init failure,
 * etc.) inside that block silently downgraded a 2FA-required login to a
 * single-factor JWT issuance.
 *
 * <p>Post-fix, the catch is narrowed to {@link DataAccessException}. Generic
 * runtime errors propagate so the request 5xx's, the user retries, and MFA is
 * enforced (fail-CLOSED). DB outages are still tolerated to keep the
 * single-factor PASSWORD path working when the auth-flow table is unreachable.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticateUserService — MFA fail-CLOSED Regression")
class AuthenticateUserServiceMfaFailClosedTest {

    private static final String VALID_BCRYPT_HASH =
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoderPort passwordEncoder;
    @Mock private TokenGenerationPort tokenGenerator;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private AuditLogPort auditLogPort;
    @Mock private EventPublisherPort eventPublisher;
    @Mock private AuthFlowRepositoryPort authFlowRepository;
    @Mock private OAuth2ClientRepositoryPort oAuth2ClientRepository;
    @Mock private UserEnrollmentRepository userEnrollmentRepository;
    @Mock private MfaSessionRepository mfaSessionRepository;
    @Mock private EnrollmentHealthService enrollmentHealthService;

    @InjectMocks
    private AuthenticateUserService authenticateUserService;

    private AuthenticateUserCommand validCommand;
    private User existingUser;
    private RefreshToken refreshToken;
    private UUID tenantId;

    @BeforeEach
    void setUp() {
        validCommand = AuthenticateUserCommand.builder()
                .email("test@example.com")
                .password("Password123!")
                .ipAddress("192.168.1.1")
                .userAgent("Mozilla/5.0")
                .build();

        tenantId = UUID.randomUUID();
        Tenant tenant = Tenant.builder()
                .id(tenantId)
                .name("test-tenant")
                .build();

        existingUser = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .tenant(tenant)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        refreshToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .token("refresh-token-value")
                .user(existingUser)
                .expiryDate(Instant.now().plus(Duration.ofDays(7)))
                .build();
    }

    @Test
    @DisplayName("Generic RuntimeException in MFA-flow lookup must propagate (fail-CLOSED, NO single-factor JWT)")
    void shouldPropagateGenericRuntimeExceptionAndNotIssueJwt() {
        // Given — password verifies, but the MFA-flow repository explodes with a
        // *non*-DataAccessException (simulates NPE, lazy-init failure, IllegalState
        // — the class of exception that previously fell through the blanket catch
        // and silently downgraded the login to single-factor).
        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(existingUser));
        when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH))
                .thenReturn(true);
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                eq(tenantId), eq(OperationType.APP_LOGIN)))
                .thenThrow(new RuntimeException("simulated NPE / lazy-init / illegal-state"));

        // When / Then — the exception MUST propagate. Pre-fix this was swallowed
        // and the method returned a successful single-factor AuthenticationResponse.
        assertThatThrownBy(() -> authenticateUserService.execute(validCommand))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("simulated NPE");

        // Critical assertion: NO access token was minted, NO refresh token was
        // created. A fail-OPEN regression would call these.
        verify(tokenGenerator, never()).generateAccessToken(any());
        verify(tokenGenerator, never()).generateAccessToken(any(), any());
        verify(refreshTokenService, never()).createRefreshToken(any(), any(), any());
    }

    @Test
    @DisplayName("DataAccessException in MFA-flow lookup is log-and-continued (single-factor PASSWORD fallback preserved)")
    void shouldLogAndContinueOnDataAccessException() {
        // Given — password verifies, MFA-flow repo throws a DB connectivity error.
        // Per the fix, DB issues are still tolerated: the user has already passed
        // the password gate and we can't reach the auth-flow table, so we fall
        // through to single-factor JWT issuance (the historical fallback intent).
        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(existingUser));
        when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH))
                .thenReturn(true);
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                eq(tenantId), eq(OperationType.APP_LOGIN)))
                .thenThrow(new DataAccessResourceFailureException("connection pool exhausted"));
        when(tokenGenerator.generateAccessToken(eq("test@example.com"), any()))
                .thenReturn("access-token");
        when(tokenGenerator.getExpirationMillis()).thenReturn(3600000L);
        when(refreshTokenService.createRefreshToken(any(), any(), any()))
                .thenReturn(refreshToken);

        // When — should NOT throw; should fall through to single-factor JWT.
        var response = authenticateUserService.execute(validCommand);

        // Then — single-factor session was issued, preserving the legacy behavior
        // that this catch was designed for.
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token-value");
        verify(refreshTokenService).createRefreshToken(existingUser, "192.168.1.1", "Mozilla/5.0");
    }
}
