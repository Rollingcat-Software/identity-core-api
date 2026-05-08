package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.VerifyBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.VerifyBiometricUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.exception.BiometricNotEnrolledException;
import com.fivucsas.identity.domain.exception.BiometricVerificationException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

/**
 * Use case service for biometric verification.
 *
 * Implements the VerifyBiometricUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class VerifyBiometricService implements VerifyBiometricUseCase {

    private final UserRepository userRepository;
    private final BiometricServicePort biometricService;
    private final com.fivucsas.identity.application.port.output.EventPublisherPort eventPublisher;

    @Override
    @Transactional
    public BiometricResponse execute(VerifyBiometricCommand command) {
        log.info("Verifying biometric for user: {}", command.getUserId());

        UUID userId = UUID.fromString(command.getUserId());
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        if (!user.isBiometricEnrolled()) {
            throw new BiometricNotEnrolledException(command.getUserId());
        }

        // Call external biometric service. Forward tenant_id +
        // client_embedding(s) for tenant-scoped pgvector matching and
        // D2 log-only client telemetry.
        Map<String, Object> response = biometricService.verifyFace(
                userId,
                command.getFaceImage(),
                command.getTenantId(),
                command.getClientEmbedding(),
                command.getClientEmbeddings());

        // biometric-processor returns "verified" (boolean), "confidence" (double),
        // "distance" (cosine distance, lower is better) and "threshold"
        // (the value distance was compared against). The latter two are
        // surfaced to the SPA via BiometricVerificationResponse so the UI can
        // stop synthesising fake sentinels (INVESTIGATION_MASTER_2026-05-07
        // §wires).
        Boolean verified = response.get("verified") != null
            ? (Boolean) response.get("verified")
            : (Boolean) response.get("success");
        String message = (String) response.get("message");
        Double confidence = numericOrNull(response.get("confidence"));
        Double distance = numericOrNull(response.get("distance"));
        Double threshold = numericOrNull(response.get("threshold"));

        if (!Boolean.TRUE.equals(verified)) {
            throw new BiometricVerificationException("Face verification failed: " + message);
        }

        // Update verification count
        user.incrementVerificationCount();
        userRepository.save(user);

        log.info("Biometric verified successfully for user: {}", user.getId());
        eventPublisher.publishBiometricVerified(command.getUserId(), true);

        return BiometricResponse.builder()
            .success(true)
            .message(message != null ? message : "Biometric verification successful")
            .confidence(confidence)
            .distance(distance)
            .threshold(threshold)
            .userId(command.getUserId())
            .build();
    }

    /**
     * Defensive numeric coercion — bio processor responses are loose maps,
     * so a value can land as {@link Number}, missing, or unexpectedly typed.
     * Returns {@code null} on any non-Number / null input rather than blowing
     * the verify response up over a telemetry field.
     */
    private static Double numericOrNull(Object value) {
        return value instanceof Number n ? n.doubleValue() : null;
    }
}
