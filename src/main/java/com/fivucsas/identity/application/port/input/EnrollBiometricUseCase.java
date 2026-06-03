package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.web.multipart.MultipartFile;

/**
 * Input port for biometric enrollment use case.
 *
 * This interface defines the contract for enrolling users
 * in biometric authentication (face recognition).
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - biometric enrollment
 * - Dependency Inversion: Application defines the port
 * - Security: Handles sensitive biometric data
 */
public interface EnrollBiometricUseCase {

    /**
     * Enrolls a user for biometric authentication.
     *
     * @param command the enrollment command containing user ID and biometric data
     * @return BiometricResponse with enrollment status and details
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     * @throws com.fivucsas.identity.domain.exception.BiometricEnrollmentException if enrollment fails
     */
    BiometricResponse execute(EnrollBiometricCommand command);

    /**
     * Marks a user as biometric-enrolled (sets {@code is_biometric_enrolled} +
     * {@code enrolled_at}). The single-image {@link #execute} path does this for FACE
     * enrollment; the multi-image enroll path ({@code POST /biometric/enroll/multi})
     * goes straight through {@code BiometricServicePort} and historically did NOT —
     * so {@code /biometric/verify} (which gates on the flag) rejected multi-enrolled
     * users with 412 "not enrolled" despite a stored embedding. The controller calls
     * this on a successful multi-enroll. Idempotent (no-op if already enrolled).
     *
     * @param userId the user to mark enrolled
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    void markBiometricEnrolled(java.util.UUID userId);

    /**
     * Multi-image face enrollment as a SINGLE atomic, transactional unit.
     *
     * <p>Calls the biometric service's multi-image enroll, then — only on a
     * robustly-parsed success — records the quality/liveness scores and flips
     * {@code is_biometric_enrolled} on the user. All three steps run in one
     * {@code @Transactional} boundary, so the database flag and the
     * user_enrollments score row can never drift apart from each other on a
     * partial failure (the previous controller-level wiring made two loose,
     * non-transactional calls and flipped the flag on a fragile
     * {@code !Boolean.FALSE.equals(success)} check — the root cause of the
     * "enrolled-in-bio-store but is_biometric_enrolled=false → 412 on verify"
     * class of bugs).</p>
     *
     * <p>Success is treated as {@code Boolean.TRUE.equals(result.get("success"))}
     * with a tolerant {@code "true"} string fallback (mirrors the voice-enroll
     * parsing). On a non-success result the bio store may or may not hold an
     * embedding, but the API flag is intentionally NOT flipped and NO exception
     * is thrown — the raw bio response (including {@code success=false} and any
     * message) is returned to the caller unchanged, preserving the existing
     * multi-enroll response contract.</p>
     *
     * @param userId           the user being enrolled
     * @param images           2-5 face images
     * @param tenantId         optional tenant id (pgvector scoping)
     * @param clientEmbedding  optional single client embedding (D2 log-only)
     * @param clientEmbeddings optional array of client embeddings (D2 log-only)
     * @param optimize         re-enroll &amp; optimize (centroid fusion) when true
     * @return the raw biometric-service response map (unchanged contract)
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if the
     *         user does not exist (only consulted on a successful bio enroll)
     */
    Map<String, Object> enrollFaceMulti(UUID userId,
                                        List<MultipartFile> images,
                                        String tenantId,
                                        String clientEmbedding,
                                        String clientEmbeddings,
                                        boolean optimize);
}
