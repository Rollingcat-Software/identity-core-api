package com.fivucsas.identity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.domain.exception.BiometricStepUpRequiredException;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.dto.BiometricChallengeResponse;
import com.fivucsas.identity.dto.BiometricRegisterDeviceRequest;
import com.fivucsas.identity.dto.BiometricStepUpTokenResponse;
import com.fivucsas.identity.dto.BiometricVerifyChallengeRequest;
import com.fivucsas.identity.entity.AuthBiometricChallenge;
import com.fivucsas.identity.entity.AuthBiometricDevice;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.AuthBiometricChallengeRepository;
import com.fivucsas.identity.repository.AuthBiometricDeviceRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class BiometricStepUpService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final AuthBiometricDeviceRepository deviceRepository;
    private final AuthBiometricChallengeRepository challengeRepository;
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    @Value("${auth.biometric.challenge-ttl-ms:90000}")
    private long challengeTtlMs;

    @Value("${auth.biometric.step-up-token-ttl-ms:300000}")
    private long stepUpTokenTtlMs;

    @Transactional
    public String registerDevice(String userEmail, BiometricRegisterDeviceRequest request) {
        User user = resolveUser(userEmail);
        validateJwk(request.getPublicKeyJwk());

        AuthBiometricDevice device = deviceRepository
                .findByUserIdAndKeyIdAndIsActiveTrue(user.getId(), request.getKeyId())
                .orElseGet(() -> AuthBiometricDevice.builder().user(user).keyId(request.getKeyId()).build());

        device.setPlatform(request.getPlatform());
        device.setDeviceLabel(request.getDeviceLabel());
        device.setPublicKeyJwk(request.getPublicKeyJwk().toString());
        device.setActive(true);

        AuthBiometricDevice saved = deviceRepository.save(device);
        return saved.getId().toString();
    }

    @Transactional
    public BiometricChallengeResponse createChallenge(String userEmail) {
        User user = resolveUser(userEmail);

        byte[] nonce = new byte[32];
        SECURE_RANDOM.nextBytes(nonce);

        UUID challengeId = UUID.randomUUID();
        Instant expiresAt = Instant.now().plusMillis(challengeTtlMs);

        AuthBiometricChallenge challenge = AuthBiometricChallenge.builder()
                .challengeId(challengeId)
                .user(user)
                .nonceBase64(Base64.getEncoder().encodeToString(nonce))
                .expiresAt(expiresAt)
                .build();
        challengeRepository.save(challenge);

        return BiometricChallengeResponse.builder()
                .challengeId(challengeId.toString())
                .nonceBase64(challenge.getNonceBase64())
                .expiresAt(expiresAt)
                .build();
    }

    @Transactional
    public BiometricStepUpTokenResponse verifyChallenge(String userEmail, BiometricVerifyChallengeRequest request) {
        User user = resolveUser(userEmail);

        UUID challengeUuid = parseUuid(request.getChallengeId(), "challengeId");
        AuthBiometricChallenge challenge = challengeRepository.findByChallengeId(challengeUuid)
                .orElseThrow(() -> new IllegalArgumentException("Challenge not found."));

        if (!challenge.getUser().getId().equals(user.getId())) {
            throw new UnauthorizedException("Challenge does not belong to authenticated user.");
        }
        if (challenge.isUsed()) {
            throw new IllegalArgumentException("Challenge already used.");
        }
        if (challenge.isExpired()) {
            throw new IllegalArgumentException("Challenge expired.");
        }

        AuthBiometricDevice device = deviceRepository
                .findByUserIdAndKeyIdAndIsActiveTrue(user.getId(), request.getKeyId())
                .orElseThrow(() -> new IllegalArgumentException("Registered biometric device not found."));

        verifySignature(device.getPublicKeyJwk(), challenge.getNonceBase64(), request.getSignatureBase64());

        challenge.markUsed();
        challengeRepository.save(challenge);

        Instant expiresAt = Instant.now().plusMillis(stepUpTokenTtlMs);
        String token = jwtService.generateStepUpToken(
                user.getEmail(),
                user.getId().toString(),
                stepUpTokenTtlMs
        );

        return BiometricStepUpTokenResponse.builder()
                .stepUpToken(token)
                .expiresAt(expiresAt)
                .build();
    }

    public void requireValidStepUp(String userEmail, String stepUpToken) {
        if (stepUpToken == null || stepUpToken.isBlank()) {
            throw new BiometricStepUpRequiredException();
        }

        User user = resolveUser(userEmail);
        try {
            if (!jwtService.isStepUpTokenValid(stepUpToken, userEmail)) {
                throw new BiometricStepUpRequiredException();
            }

            String tokenUserId = jwtService.extractUserId(stepUpToken);
            if (tokenUserId == null || !tokenUserId.equals(user.getId().toString())) {
                throw new BiometricStepUpRequiredException("Biometric step-up token does not match authenticated user.");
            }
        } catch (BiometricStepUpRequiredException e) {
            throw e;
        } catch (Exception e) {
            throw new BiometricStepUpRequiredException();
        }
    }

    private void verifySignature(String publicKeyJwkJson, String nonceBase64, String signatureBase64) {
        try {
            JsonNode jwk = objectMapper.readTree(publicKeyJwkJson);
            PublicKey publicKey = publicKeyFromJwk(jwk);

            byte[] nonce = Base64.getDecoder().decode(nonceBase64);
            byte[] signature = decodeBase64(signatureBase64);

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(nonce);

            if (!verifier.verify(signature)) {
                throw new IllegalArgumentException("Biometric signature verification failed.");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to verify biometric signature.", e);
        }
    }

    private PublicKey publicKeyFromJwk(JsonNode jwk) throws Exception {
        validateJwk(jwk);

        byte[] x = Base64.getUrlDecoder().decode(jwk.get("x").asText());
        byte[] y = Base64.getUrlDecoder().decode(jwk.get("y").asText());
        ECPoint ecPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    private void validateJwk(JsonNode jwk) {
        if (jwk == null || jwk.isNull()) {
            throw new IllegalArgumentException("publicKeyJwk is required.");
        }

        String kty = textValue(jwk, "kty");
        String crv = textValue(jwk, "crv");
        String x = textValue(jwk, "x");
        String y = textValue(jwk, "y");

        if (!"EC".equals(kty)) {
            throw new IllegalArgumentException("JWK kty must be EC.");
        }
        if (!"P-256".equals(crv)) {
            throw new IllegalArgumentException("JWK crv must be P-256.");
        }
        if (x == null || y == null) {
            throw new IllegalArgumentException("JWK must include x and y coordinates.");
        }
    }

    private String textValue(JsonNode node, String fieldName) {
        JsonNode field = node.get(fieldName);
        return (field == null || field.isNull()) ? null : field.asText();
    }

    private UUID parseUuid(String value, String fieldName) {
        try {
            return UUID.fromString(value);
        } catch (Exception e) {
            throw new IllegalArgumentException(fieldName + " must be a valid UUID.");
        }
    }

    private byte[] decodeBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (Exception ignored) {
            return Base64.getUrlDecoder().decode(value);
        }
    }

    private User resolveUser(String userEmail) {
        return userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotFoundException(userEmail));
    }
}
