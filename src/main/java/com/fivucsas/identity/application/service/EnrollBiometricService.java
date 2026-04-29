package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.EnrollBiometricUseCase;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.exception.BiometricEnrollmentException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Map;
import java.util.UUID;

/**
 * Use case service for biometric enrollment.
 *
 * Implements the EnrollBiometricUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EnrollBiometricService implements EnrollBiometricUseCase {

    private final UserRepository userRepository;
    private final BiometricServicePort biometricService;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;
    private final com.fivucsas.identity.application.port.output.EventPublisherPort eventPublisher;

    @Override
    @Transactional
    public BiometricResponse execute(EnrollBiometricCommand command) {
        log.info("Enrolling biometric for user: {}", command.getUserId());

        UUID userId = UUID.fromString(command.getUserId());
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        // Call external biometric service. Forward tenant_id +
        // client_embedding(s) so pgvector queries can be tenant-scoped and
        // D2 log-only client telemetry survives the proxy hop.
        Map<String, Object> response = biometricService.enrollFace(
                userId,
                command.getFaceImage(),
                command.getTenantId(),
                command.getClientEmbedding(),
                command.getClientEmbeddings());

        Boolean success = (Boolean) response.get("success");
        String message = (String) response.get("message");

        if (!Boolean.TRUE.equals(success)) {
            throw new BiometricEnrollmentException("Face enrollment failed: " + message);
        }

        // Update user enrollment status
        user.enrollBiometric();
        userRepository.save(user);

        // Best-effort: persist quality + liveness scores from biometric-processor
        // onto the matching user_enrollments row so the admin Enrollments table
        // can render real numbers instead of "-". Silently no-ops if the row
        // hasn't been started yet.
        try {
            manageEnrollmentUseCase.recordBiometricScores(
                userId,
                AuthMethodType.FACE,
                extractScore(response, "quality_score"),
                extractScore(response, "liveness_score"));
        } catch (Exception e) {
            log.warn("Failed to persist enrollment scores for user {}: {}", userId, e.getMessage());
        }

        log.info("Biometric enrolled successfully for user: {}", user.getId());
        eventPublisher.publishBiometricEnrolled(command.getUserId());

        return BiometricResponse.builder()
            .success(true)
            .message(message != null ? message : "Biometric enrollment successful")
            .userId(command.getUserId())
            .build();
    }

    /**
     * Extract a 0..1 score from the biometric-processor response. Tolerates
     * Number, numeric string, or absent / null values. Returns null when the
     * value is missing or unparseable so the DB CHECK constraint isn't tripped.
     * Values in (1, 100] are rescaled assuming 0..100 percent style; out-of-
     * range values are clamped to [0, 1].
     */
    public static BigDecimal extractScore(Map<String, Object> response, String key) {
        if (response == null) {
            return null;
        }
        Object raw = response.get(key);
        if (raw == null) {
            return null;
        }
        try {
            BigDecimal value;
            if (raw instanceof Number n) {
                value = BigDecimal.valueOf(n.doubleValue());
            } else {
                value = new BigDecimal(raw.toString().trim());
            }
            if (value.compareTo(BigDecimal.ONE) > 0
                    && value.compareTo(BigDecimal.valueOf(100)) <= 0) {
                value = value.divide(BigDecimal.valueOf(100), 4, RoundingMode.HALF_UP);
            }
            if (value.compareTo(BigDecimal.ZERO) < 0) {
                return BigDecimal.ZERO;
            }
            if (value.compareTo(BigDecimal.ONE) > 0) {
                return BigDecimal.ONE;
            }
            return value.setScale(4, RoundingMode.HALF_UP);
        } catch (NumberFormatException ex) {
            return null;
        }
    }
}
