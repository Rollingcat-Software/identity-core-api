package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.infrastructure.totp.TotpService;
import com.fivucsas.identity.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.ResponseEntity;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("TotpController Tests")
class TotpControllerTest {

    @Mock private TotpService totpService;
    @Mock private UserRepository userRepository;
    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOps;

    @InjectMocks
    private TotpController totpController;

    private UUID userId;
    private User testUser;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        testUser = User.builder()
                .id(userId)
                .email("test@example.com")
                .passwordHash("$2a$10$hash")
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .build();
    }

    @Nested
    @DisplayName("Setup TOTP")
    class SetupTotp {

        @Test
        @DisplayName("Should setup TOTP and return secret and URI")
        void shouldSetupTotp() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(totpService.generateSecret()).thenReturn("JBSWY3DPEHPK3PXP");
            when(totpService.buildOtpAuthUri("JBSWY3DPEHPK3PXP", "test@example.com", "FivucsasIdentity"))
                    .thenReturn("otpauth://totp/FivucsasIdentity:test@example.com?secret=JBSWY3DPEHPK3PXP");
            when(redisTemplate.opsForValue()).thenReturn(valueOps);

            ResponseEntity<Map<String, Object>> response = totpController.setupTotp(userId);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("secret", "JBSWY3DPEHPK3PXP");
            assertThat(response.getBody()).containsKey("otpAuthUri");
            verify(valueOps).set(eq("totp:secret:pending:" + userId), eq("JBSWY3DPEHPK3PXP"), any(Duration.class));
        }

        @Test
        @DisplayName("Should throw when user not found for setup")
        void shouldThrowWhenUserNotFound() {
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> totpController.setupTotp(userId))
                    .isInstanceOf(EntityNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("Verify TOTP Setup")
    class VerifySetup {

        @Test
        @DisplayName("Should verify TOTP setup with valid code")
        void shouldVerifySetup() {
            when(redisTemplate.opsForValue()).thenReturn(valueOps);
            when(valueOps.get("totp:secret:pending:" + userId)).thenReturn("JBSWY3DPEHPK3PXP");
            when(totpService.verifyCode("JBSWY3DPEHPK3PXP", "123456")).thenReturn(true);

            ResponseEntity<Map<String, Object>> response =
                    totpController.verifyTotpSetup(userId, Map.of("code", "123456"));

            assertThat(response.getBody()).containsEntry("success", true);
            verify(valueOps).set("totp:secret:" + userId, "JBSWY3DPEHPK3PXP");
            verify(redisTemplate).delete("totp:secret:pending:" + userId);
        }

        @Test
        @DisplayName("Should reject invalid TOTP code")
        void shouldRejectInvalidCode() {
            when(redisTemplate.opsForValue()).thenReturn(valueOps);
            when(valueOps.get("totp:secret:pending:" + userId)).thenReturn("JBSWY3DPEHPK3PXP");
            when(totpService.verifyCode("JBSWY3DPEHPK3PXP", "000000")).thenReturn(false);

            ResponseEntity<Map<String, Object>> response =
                    totpController.verifyTotpSetup(userId, Map.of("code", "000000"));

            assertThat(response.getBody()).containsEntry("success", false);
        }

        @Test
        @DisplayName("Should reject when no pending setup")
        void shouldRejectWhenNoPendingSetup() {
            when(redisTemplate.opsForValue()).thenReturn(valueOps);
            when(valueOps.get("totp:secret:pending:" + userId)).thenReturn(null);

            ResponseEntity<Map<String, Object>> response =
                    totpController.verifyTotpSetup(userId, Map.of("code", "123456"));

            assertThat(response.getStatusCode().value()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should reject blank code")
        void shouldRejectBlankCode() {
            ResponseEntity<Map<String, Object>> response =
                    totpController.verifyTotpSetup(userId, Map.of("code", ""));

            assertThat(response.getStatusCode().value()).isEqualTo(400);
        }
    }

    @Nested
    @DisplayName("TOTP Status")
    class TotpStatus {

        @Test
        @DisplayName("Should return configured when TOTP key exists")
        void shouldReturnConfiguredTrue() {
            when(redisTemplate.hasKey("totp:secret:" + userId)).thenReturn(true);

            ResponseEntity<Map<String, Object>> response = totpController.getTotpStatus(userId);

            assertThat(response.getBody()).containsEntry("configured", true);
        }

        @Test
        @DisplayName("Should return not configured when no TOTP key")
        void shouldReturnConfiguredFalse() {
            when(redisTemplate.hasKey("totp:secret:" + userId)).thenReturn(false);

            ResponseEntity<Map<String, Object>> response = totpController.getTotpStatus(userId);

            assertThat(response.getBody()).containsEntry("configured", false);
        }
    }

    @Nested
    @DisplayName("Revoke TOTP")
    class RevokeTotp {

        @Test
        @DisplayName("Should revoke TOTP and delete keys")
        void shouldRevokeTotp() {
            ResponseEntity<Map<String, Object>> response = totpController.revokeTotp(userId);

            assertThat(response.getBody()).containsEntry("success", true);
            verify(redisTemplate).delete("totp:secret:" + userId);
            verify(redisTemplate).delete("totp:secret:pending:" + userId);
        }
    }
}
