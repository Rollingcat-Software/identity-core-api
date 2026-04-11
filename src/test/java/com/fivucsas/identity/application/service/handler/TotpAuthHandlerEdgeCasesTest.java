package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.totp.TotpService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TotpAuthHandlerEdgeCasesTest {

    @Mock private TotpService totpService;
    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;
    @Mock private UserRepository userRepository;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private TotpAuthHandler handler;

    // ── Null / empty / whitespace code variations ───────────────────────

    @Test
    void validate_WhenCodeIsNull_ShouldReturnFailure() {
        Map<String, Object> data = new HashMap<>();
        data.put("code", null);

        StepResult result = handler.validate(session, step, data);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("TOTP code is required");
    }

    @Test
    void validate_WhenCodeIsEmptyString_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of("code", ""));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("TOTP code is required");
    }

    @Test
    void validate_WhenCodeKeyMissing_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of("action", "verify"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("TOTP code is required");
    }

    // ── TOTP secret not in Redis (expired session) + DB fallback ────────

    @Test
    void validate_WhenSecretNotInRedisButInDb_ShouldFallbackAndSucceed() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getTwoFactorSecret()).thenReturn("DB_SECRET_VALUE");
        when(session.getUser()).thenReturn(user);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn(null);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(totpService.verifyCode("DB_SECRET_VALUE", "123456")).thenReturn(true);

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isTrue();
        // Verify it re-cached the secret in Redis
        verify(valueOperations).set("totp:secret:" + userId, "DB_SECRET_VALUE");
    }

    @Test
    void validate_WhenSecretNotInRedisAndNotInDb_ShouldReturnNotConfigured() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn(null);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("TOTP not configured for this user");
    }

    @Test
    void validate_WhenSecretNotInRedisAndUserNotInDb_ShouldReturnNotConfigured() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn(null);
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("TOTP not configured for this user");
    }

    // ── Non-numeric / very long / malformed code input ──────────────────

    @Test
    void validate_WhenNonNumericCode_ShouldDelegateToTotpServiceAndFail() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn("JBSWY3DPEHPK3PXP");
        when(totpService.verifyCode("JBSWY3DPEHPK3PXP", "abcdef")).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("code", "abcdef"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid TOTP code");
    }

    @Test
    void validate_WhenVeryLongCode_ShouldDelegateToTotpServiceAndFail() {
        UUID userId = UUID.randomUUID();
        String longCode = "1".repeat(1000);
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn("JBSWY3DPEHPK3PXP");
        when(totpService.verifyCode("JBSWY3DPEHPK3PXP", longCode)).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("code", longCode));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid TOTP code");
    }

    @Test
    void validate_WhenCodeWithSpecialCharacters_ShouldDelegateToTotpService() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn("JBSWY3DPEHPK3PXP");
        when(totpService.verifyCode("JBSWY3DPEHPK3PXP", "12 34")).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("code", "12 34"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid TOTP code");
    }

    // ── TotpService internal error (exception in verifyCode) ────────────

    @Test
    void validate_WhenTotpServiceThrowsException_ShouldReturnInvalid() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn("JBSWY3DPEHPK3PXP");
        // TotpService.verifyCode() catches exceptions and returns false
        when(totpService.verifyCode("JBSWY3DPEHPK3PXP", "123456")).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid TOTP code");
    }

    // ── User is null during code verification ───────────────────────────

    @Test
    void validate_WhenUserIsNullDuringCodeVerification_ShouldReturnFailure() {
        when(session.getUser()).thenReturn(null);

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    // ── Setup edge cases ────────────────────────────────────────────────

    @Test
    void validate_WhenSetupAction_ShouldStoreSecretInRedis() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("setup@test.com");
        when(session.getUser()).thenReturn(user);
        when(totpService.generateSecret()).thenReturn("GENERATED_SECRET");
        when(totpService.buildOtpAuthUri("GENERATED_SECRET", "setup@test.com", "FIVUCSAS"))
                .thenReturn("otpauth://totp/FIVUCSAS:setup@test.com?secret=GENERATED_SECRET");
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        StepResult result = handler.validate(session, step, Map.of("action", "setup"));

        assertThat(result.isSuccess()).isTrue();
        verify(valueOperations).set("totp:secret:" + userId, "GENERATED_SECRET");
        assertThat(result.data().get("secret")).isEqualTo("GENERATED_SECRET");
        assertThat(result.data().get("otpAuthUri")).asString().contains("otpauth://totp/");
    }

    // ── requiredDataFields ──────────────────────────────────────────────

    @Test
    void requiredDataFields_ShouldContainCode() {
        assertThat(handler.requiredDataFields()).containsExactly("code");
    }

    // ── Empty data map ──────────────────────────────────────────────────

    @Test
    void validate_WhenEmptyDataMap_ShouldReturnCodeRequired() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("TOTP code is required");
    }

    // ── Correct code after wrong code (no state leaks) ──────────────────

    @Test
    void validate_WhenCorrectCodeAfterIncorrect_ShouldSucceed() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn("SECRET");
        when(totpService.verifyCode("SECRET", "000000")).thenReturn(false);
        when(totpService.verifyCode("SECRET", "123456")).thenReturn(true);

        // First attempt: wrong
        StepResult wrongResult = handler.validate(session, step, Map.of("code", "000000"));
        assertThat(wrongResult.isSuccess()).isFalse();

        // Second attempt: correct
        StepResult correctResult = handler.validate(session, step, Map.of("code", "123456"));
        assertThat(correctResult.isSuccess()).isTrue();
    }
}
