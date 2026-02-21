package com.fivucsas.identity.infrastructure.stepup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.security.*;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StepUpChallengeServiceTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private StepUpChallengeService service;

    @Test
    void generateChallenge_ShouldStoreInRedisAndReturnBase64UrlString() {
        UUID userId = UUID.randomUUID();
        String deviceFingerprint = "device-001";
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        String challenge = service.generateChallenge(userId, deviceFingerprint);

        assertThat(challenge).isNotBlank();
        // base64url without padding — should not contain +, /, or =
        assertThat(challenge).doesNotContain("+", "/", "=");
        // 32 bytes → 43 base64url chars (no padding)
        assertThat(challenge).hasSize(43);

        String expectedKey = "stepup:challenge:" + userId + ":" + deviceFingerprint;
        verify(valueOperations).set(eq(expectedKey), eq(challenge), eq(Duration.ofMinutes(5)));
    }

    @Test
    void generateChallenge_ShouldGenerateUniqueValuesPerCall() {
        UUID userId = UUID.randomUUID();
        String deviceFingerprint = "device-001";
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        String challenge1 = service.generateChallenge(userId, deviceFingerprint);
        String challenge2 = service.generateChallenge(userId, deviceFingerprint);

        assertThat(challenge1).isNotEqualTo(challenge2);
    }

    @Test
    void consumeChallenge_WhenExists_ShouldReturnAndDelete() {
        UUID userId = UUID.randomUUID();
        String deviceFingerprint = "device-001";
        String expectedKey = "stepup:challenge:" + userId + ":" + deviceFingerprint;
        String storedChallenge = "abc123challenge";

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(expectedKey)).thenReturn(storedChallenge);

        String result = service.consumeChallenge(userId, deviceFingerprint);

        assertThat(result).isEqualTo(storedChallenge);
        verify(redisTemplate).delete(expectedKey);
    }

    @Test
    void consumeChallenge_WhenNotExists_ShouldReturnNull() {
        UUID userId = UUID.randomUUID();
        String deviceFingerprint = "device-001";
        String expectedKey = "stepup:challenge:" + userId + ":" + deviceFingerprint;

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(expectedKey)).thenReturn(null);

        String result = service.consumeChallenge(userId, deviceFingerprint);

        assertThat(result).isNull();
        verify(redisTemplate, never()).delete(anyString());
    }

    @Test
    void verifySignature_WithValidEcdsaSignature_ShouldReturnTrue() throws Exception {
        KeyPair keyPair = generateEcKeyPair();

        byte[] challengeBytes = new byte[32];
        new SecureRandom().nextBytes(challengeBytes);
        String challengeBase64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);

        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String signatureBase64 = sign(keyPair.getPrivate(), challengeBytes);

        boolean result = service.verifySignature(publicKeyBase64, challengeBase64Url, signatureBase64);

        assertThat(result).isTrue();
    }

    @Test
    void verifySignature_WithInvalidSignature_ShouldReturnFalse() throws Exception {
        KeyPair keyPair = generateEcKeyPair();

        byte[] challengeBytes = new byte[32];
        new SecureRandom().nextBytes(challengeBytes);
        String challengeBase64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);

        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String badSignature = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4, 5});

        boolean result = service.verifySignature(publicKeyBase64, challengeBase64Url, badSignature);

        assertThat(result).isFalse();
    }

    @Test
    void verifySignature_WithMalformedPublicKey_ShouldReturnFalse() {
        String malformedKey = Base64.getEncoder().encodeToString(new byte[]{0, 1, 2, 3});
        String challengeBase64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
        String signatureBase64 = Base64.getEncoder().encodeToString(new byte[]{5, 6, 7, 8});

        boolean result = service.verifySignature(malformedKey, challengeBase64Url, signatureBase64);

        assertThat(result).isFalse();
    }

    @Test
    void getChallengeExpiresInSeconds_ShouldReturn300() {
        assertThat(service.getChallengeExpiresInSeconds()).isEqualTo(300L);
    }

    // --- Helpers ---

    private KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    private String sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(data);
        return Base64.getEncoder().encodeToString(sig.sign());
    }
}
