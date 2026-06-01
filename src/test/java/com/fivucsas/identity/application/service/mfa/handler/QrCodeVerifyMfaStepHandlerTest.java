package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * P1-2 regression: a QR token issued by {@link QrCodeService#generateToken}
 * must verify through {@link QrCodeVerifyMfaStepHandler} on the live
 * {@code POST /auth/mfa/step} path.
 *
 * <p>Before the fix the handler validated against
 * {@code otpService.validate("2fa-qr:" + userId, token)} — a Redis store
 * NOTHING ever writes — so QR as a 2nd factor always failed. The handler now
 * delegates to {@link QrCodeService#validateToken(String, UUID)} (the same
 * token-keyed store written by {@code generateToken} and consumed by the
 * working {@code QrCodeAuthHandler}).
 *
 * <p>This test drives a REAL {@link QrCodeService} backed by an in-memory
 * fake of {@link StringRedisTemplate}/{@link ValueOperations}, so the
 * generate → verify round-trip is exercised end-to-end through the actual
 * key derivation rather than a stubbed boolean.
 */
@ExtendWith(MockitoExtension.class)
class QrCodeVerifyMfaStepHandlerTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOps;

    /** In-memory backing for the faked Redis value store. */
    private final Map<String, String> store = new HashMap<>();

    private QrCodeService qrCodeService;
    private QrCodeVerifyMfaStepHandler handler;

    @BeforeEach
    void setUp() {
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOps);
        // set(key, value, ttl) → write into the in-memory map
        lenient().doAnswer(inv -> {
            store.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(valueOps).set(anyString(), anyString(), any(Duration.class));
        // get(key) → read from the in-memory map
        lenient().when(valueOps.get(anyString())).thenAnswer(inv -> store.get(inv.getArgument(0)));
        // delete(key) → consume the token (single-use)
        lenient().when(redisTemplate.delete(anyString()))
                .thenAnswer(inv -> store.remove(inv.getArgument(0)) != null);

        // Real QrCodeService over the in-memory Redis fake; the handler wraps it.
        qrCodeService = new QrCodeService(redisTemplate);
        handler = new QrCodeVerifyMfaStepHandler(qrCodeService);
    }

    @Test
    void verify_tokenGeneratedByQrCodeService_passesThroughMfaStepHandler() {
        UUID userId = UUID.randomUUID();

        String token = qrCodeService.generateToken(userId);
        assertThat(token).isNotBlank();

        MfaSession session = mock(MfaSession.class);
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        MfaStepResult result = handler.verify(session, user, Map.of("token", token));

        assertThat(result.valid())
                .as("a QrCodeService-issued token must verify through the MFA-step handler")
                .isTrue();
    }

    @Test
    void verify_tokenIsSingleUse_secondVerifyFails() {
        UUID userId = UUID.randomUUID();
        String token = qrCodeService.generateToken(userId);

        MfaSession session = mock(MfaSession.class);
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        assertThat(handler.verify(session, user, Map.of("token", token)).valid()).isTrue();
        // Token was consumed on first use — replay must fail.
        assertThat(handler.verify(session, user, Map.of("token", token)).valid()).isFalse();
    }

    @Test
    void verify_tokenBoundToAnotherUser_fails() {
        UUID owner = UUID.randomUUID();
        UUID attacker = UUID.randomUUID();
        String token = qrCodeService.generateToken(owner);

        MfaSession session = mock(MfaSession.class);
        User attackerUser = mock(User.class);
        when(attackerUser.getId()).thenReturn(attacker);

        MfaStepResult result = handler.verify(session, attackerUser, Map.of("token", token));
        assertThat(result.valid()).isFalse();
    }

    @Test
    void verify_missingOrBlankToken_fails() {
        MfaSession session = mock(MfaSession.class);
        User user = mock(User.class);

        assertThat(handler.verify(session, user, Map.of()).valid()).isFalse();
        assertThat(handler.verify(session, user, Map.of("token", "")).valid()).isFalse();
    }

    @Test
    void supports_isQrCode() {
        assertThat(handler.supports())
                .isEqualTo(com.fivucsas.identity.domain.model.auth.AuthMethodType.QR_CODE);
    }
}
