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

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TotpAuthHandlerTest {

    @Mock private TotpService totpService;
    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;
    @Mock private UserRepository userRepository;
    @Mock private com.fivucsas.identity.security.TotpSecretCipher totpSecretCipher;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private TotpAuthHandler handler;

    @Test
    void getMethodType_ShouldReturnTotp() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.TOTP);
    }

    @Test
    void validate_WhenValidCode_ShouldReturnSuccess() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn("JBSWY3DPEHPK3PXP");
        when(totpService.verifyCode("JBSWY3DPEHPK3PXP", "123456")).thenReturn(true);

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void validate_WhenInvalidCode_ShouldReturnFailure() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn("JBSWY3DPEHPK3PXP");
        when(totpService.verifyCode("JBSWY3DPEHPK3PXP", "000000")).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("code", "000000"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid TOTP code");
    }

    @Test
    void validate_WhenMissingCode_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("TOTP code is required");
    }

    @Test
    void validate_WhenNoTotpConfigured_ShouldReturnFailure() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("totp:secret:" + userId)).thenReturn(null);
        // Redis miss → DB fallback; user absent or has no 2FA secret
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("TOTP not configured for this user");
    }

    @Test
    void validate_WhenSetupAction_ShouldReturnSecretAndUri() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("test@test.com");
        when(session.getUser()).thenReturn(user);
        when(totpService.generateSecret()).thenReturn("NEWSECRET");
        when(totpService.buildOtpAuthUri("NEWSECRET", "test@test.com", "FIVUCSAS"))
                .thenReturn("otpauth://totp/FIVUCSAS:test@test.com?secret=NEWSECRET");
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        StepResult result = handler.validate(session, step, Map.of("action", "setup"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsKey("secret");
        assertThat(result.data()).containsKey("otpAuthUri");
    }

    @Test
    void validate_WhenSetupWithoutUser_ShouldFail() {
        when(session.getUser()).thenReturn(null);

        StepResult result = handler.validate(session, step, Map.of("action", "setup"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    @Test
    void requiresEnrollment_ShouldReturnTrue() {
        assertThat(handler.requiresEnrollment()).isTrue();
    }
}
