package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.EnrollBiometricUseCase;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.exception.BiometricEnrollmentException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;
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
    private final UserDomainRepository userDomainRepository;
    private final BiometricServicePort biometricService;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;
    private final com.fivucsas.identity.application.port.output.EventPublisherPort eventPublisher;
    // Phase 5 (sub-project A): gates the client-side-embedding enroll path.
    // Default OFF ⇒ the legacy image enroll below is byte-identical to before.
    private final ClientSideEmbeddingPolicy clientSideEmbeddingPolicy;

    @Override
    @Transactional
    public BiometricResponse execute(EnrollBiometricCommand command) {
        log.info("Enrolling biometric for user: {}", command.getUserId());

        UUID userId = UUID.fromString(command.getUserId());
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        // ROUTING (Phase 5, sub-project A): when the client-side-embedding path is
        // ON for this tenant AND the command carries a precomputed embedding (the
        // raw image never left the device), enroll via the bio /enroll-embedding
        // endpoint. Otherwise fall through to the UNCHANGED legacy image enroll.
        // Default OFF (policy + no embedding) ⇒ identical to the pre-Phase-5
        // behaviour. SECURITY: the embedding carries no frame, so the bio
        // processor cannot run liveness/anti-spoof on it — an embedding FACE
        // factor MUST be paired with a liveness factor (puzzle/passive) in the
        // flow (enforced by sub-projects B/C); this only routes the enroll.
        List<Double> embedding = command.getEmbedding();
        boolean hasEmbedding = embedding != null && !embedding.isEmpty();
        Map<String, Object> response;
        // Mirror FaceVerifyMfaStepHandler's predicate exactly: an embedding is
        // routed to the new endpoint ONLY when one is present AND the policy is
        // ON for the tenant; otherwise the legacy image enroll is used unchanged.
        // Phase 6: this branch is now reachable — the JSON enroll endpoint
        // (POST /api/v1/biometric/enroll-embedding/{userId}) populates
        // command.embedding (the multipart enroll controller cannot carry a
        // List<Double>). The controller already fail-closes when the policy is
        // OFF for the tenant, so a JSON request with the flag off never reaches
        // here with an embedding; the policy re-check below is defense-in-depth.
        if (hasEmbedding && clientSideEmbeddingPolicy.isEnabledForTenant(command.getTenantId())) {
            response = biometricService.enrollEmbedding(command.getTenantId(), userId, embedding);
        } else {
            // Call external biometric service. Forward tenant_id +
            // client_embedding(s) so pgvector queries can be tenant-scoped and
            // D2 log-only client telemetry survives the proxy hop.
            response = biometricService.enrollFace(
                    userId,
                    command.getFaceImage(),
                    command.getTenantId(),
                    command.getClientEmbedding(),
                    command.getClientEmbeddings(),
                    command.isOptimize());
        }

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

    @Override
    @Transactional
    public Map<String, Object> enrollFaceMulti(UUID userId,
                                               List<MultipartFile> images,
                                               String tenantId,
                                               String clientEmbedding,
                                               String clientEmbeddings,
                                               boolean optimize) {
        log.info("Multi-image biometric enrollment for user: {} ({} images, optimize: {})",
                userId, images != null ? images.size() : 0, optimize);

        // 1) Call the external biometric service. This persists the embedding
        //    in the bio face store (separate database) when it succeeds.
        Map<String, Object> result = biometricService.enrollFaceMulti(
                userId, images, tenantId, clientEmbedding, clientEmbeddings, optimize);

        // 2) Parse success ROBUSTLY. The bio proxy returns success=false on an
        //    error (errorResponse()), success=true on a clean enroll. We treat
        //    ONLY an explicit truthy value as success — NOT the previous
        //    !Boolean.FALSE.equals(...) which also flipped the flag when
        //    "success" was missing/null/non-boolean. Mirrors the voice-enroll
        //    tolerant parsing for an older bio build returning "true" as a string.
        if (!isSuccess(result)) {
            log.warn("Multi-image enrollment did not succeed for user {} — NOT flipping is_biometric_enrolled. Response: {}",
                    userId, result);
            return result;
        }

        // 3) Best-effort: persist quality + liveness scores onto the matching
        //    user_enrollments row. Inside the transaction but defensive: admin
        //    bookkeeping must never fail the enrollment.
        try {
            manageEnrollmentUseCase.recordBiometricScores(
                    userId,
                    AuthMethodType.FACE,
                    extractScore(result, "quality_score"),
                    extractScore(result, "liveness_score"));
        } catch (Exception e) {
            log.warn("Failed to persist multi-enroll scores for user {}: {}", userId, e.getMessage());
        }

        // 4) Flip is_biometric_enrolled (+ enrolled_at) in the SAME transaction
        //    as the score write, so the flag and the bio embedding can no longer
        //    drift apart on a partial failure.
        markBiometricEnrolledInternal(userId);

        return result;
    }

    /**
     * Tolerant success parsing for the loose biometric-processor response map:
     * an explicit boolean {@code true}, or the string {@code "true"} (older bio
     * builds). Anything else — including a missing/null/non-boolean value — is
     * treated as NOT a success, so the flag is never flipped speculatively.
     */
    private static boolean isSuccess(Map<String, Object> result) {
        if (result == null) {
            return false;
        }
        Object success = result.get("success");
        return Boolean.TRUE.equals(success)
                || "true".equalsIgnoreCase(String.valueOf(success));
    }

    @Override
    @Transactional
    public void markBiometricEnrolled(UUID userId) {
        markBiometricEnrolledInternal(userId);
    }

    /**
     * Flag-flip shared by {@link #markBiometricEnrolled(UUID)} and the atomic
     * {@link #enrollFaceMulti} path. NOT annotated {@code @Transactional} itself
     * so that, when called from {@code enrollFaceMulti}, it joins the caller's
     * transaction (a self-invocation would otherwise bypass the proxy and run
     * non-transactionally). The public {@code markBiometricEnrolled} keeps its
     * own transaction for external callers.
     */
    private void markBiometricEnrolledInternal(UUID userId) {
        // Uses the domain repository + domain User (hexagonal boundary: application
        // code must not depend on entity.User — see UserDomainBoundaryTest). The
        // domain->entity adapter maps is_biometric_enrolled + enrolled_at, so the flag
        // persists. `var` keeps the type as domain.model.user.User (the entity.User
        // import above is only for the single-image execute() path).
        var user = userDomainRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(userId.toString()));
        if (!user.hasBiometricEnrolled()) {
            user.enrollBiometric();
            userDomainRepository.save(user);
            log.info("Marked user {} biometric-enrolled (multi-image enroll path)", userId);
        }
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
