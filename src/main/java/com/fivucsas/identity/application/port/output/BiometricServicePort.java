package com.fivucsas.identity.application.port.output;

import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Output port for biometric service operations.
 *
 * This interface defines the contract for external biometric services.
 * The application layer defines what it needs, and the infrastructure
 * layer provides the implementation (FastAPI adapter).
 *
 * Following principles:
 * - Dependency Inversion: Application defines the port, infrastructure implements
 * - Interface Segregation: Only biometric-related operations
 * - Adapter Pattern: Abstracts external service details
 */
public interface BiometricServicePort {

    /**
     * Checks the health of the biometric processor service.
     *
     * @return Map containing health status data (status, version, model, detector)
     */
    Map<String, Object> checkHealth();

    /**
     * Enrolls a user's face in the biometric system.
     *
     * @param userId the user ID
     * @param faceImage the face image file
     * @return Map containing enrollment response data
     * @throws com.fivucsas.identity.domain.exception.BiometricEnrollmentException if enrollment fails
     */
    default Map<String, Object> enrollFace(UUID userId, MultipartFile faceImage) {
        return enrollFace(userId, faceImage, null, null, null);
    }

    /**
     * Enrolls a user's face with tenant scoping and optional client-side
     * pre-filter embedding telemetry (D2 log-only).
     *
     * @param userId the user ID
     * @param faceImage the face image file
     * @param tenantId optional tenant identifier — required for pgvector tenant
     *                 scoping on the bio side
     * @param clientEmbedding optional single 512-dim client embedding (JSON
     *                        array string). D2 architectural decision: log-only,
     *                        not used for auth.
     * @param clientEmbeddings optional array-of-arrays of client embeddings
     *                         (JSON string). Either field may be null/empty.
     * @return Map containing enrollment response data
     */
    default Map<String, Object> enrollFace(UUID userId,
                                           MultipartFile faceImage,
                                           String tenantId,
                                           String clientEmbedding,
                                           String clientEmbeddings) {
        return enrollFace(userId, faceImage, tenantId, clientEmbedding, clientEmbeddings, false);
    }

    /**
     * Enrolls a user's face, optionally as a "re-enroll &amp; optimize" — when
     * {@code optimize} is true and the user already has a stored template, the
     * biometric-processor FUSES this capture into the existing centroid instead
     * of a plain append/replace (improves robustness across captures). When
     * false, behaviour is identical to the legacy enroll. The flag is forwarded
     * to the bio {@code /enroll} endpoint as the {@code optimize} multipart
     * field; an older bio build that doesn't know the field simply ignores it
     * (graceful fallback to plain re-enroll).
     */
    Map<String, Object> enrollFace(UUID userId,
                                   MultipartFile faceImage,
                                   String tenantId,
                                   String clientEmbedding,
                                   String clientEmbeddings,
                                   boolean optimize);

    /**
     * Verifies a user's face against enrolled biometric data.
     *
     * @param userId the user ID
     * @param faceImage the face image file to verify
     * @return Map containing verification response data
     * @throws com.fivucsas.identity.domain.exception.BiometricVerificationException if verification fails
     */
    default Map<String, Object> verifyFace(UUID userId, MultipartFile faceImage) {
        return verifyFace(userId, faceImage, null, null, null);
    }

    /**
     * Verifies a user's face with tenant scoping and optional client-side
     * pre-filter embedding telemetry (D2 log-only).
     */
    Map<String, Object> verifyFace(UUID userId,
                                   MultipartFile faceImage,
                                   String tenantId,
                                   String clientEmbedding,
                                   String clientEmbeddings);

    /**
     * Verifies a user's face from a CLIENT-SIDE precomputed embedding (512-dim
     * Facenet512 vector) instead of an image — sub-project A "world-ready" path,
     * where the embedding is computed in the browser so the raw face image never
     * leaves the device. Routes to the biometric-processor's
     * {@code POST /verify-embedding} endpoint.
     *
     * <p>Gated by {@code ClientSideEmbeddingPolicy} at the call site; the legacy
     * image {@link #verifyFace} path is unchanged. The embedding alone carries no
     * frame, so server-side liveness/anti-spoof cannot run on it — an embedding
     * FACE factor MUST be paired with a liveness factor (puzzle/passive) in the
     * auth flow (enforced by sub-projects B/C).
     *
     * @param tenantId  optional tenant identifier — for pgvector tenant scoping
     *                  on the bio side (null/blank → bio default tenant)
     * @param userId    the user ID to verify against
     * @param embedding the 512-dim client-side embedding (list of floats)
     * @return Map containing verification response data (e.g. {@code verified})
     */
    Map<String, Object> verifyEmbedding(String tenantId, UUID userId, List<Double> embedding);

    /**
     * Enrolls a user's face from a CLIENT-SIDE precomputed embedding (512-dim
     * Facenet512 vector) instead of an image — sub-project A path. Routes to the
     * biometric-processor's {@code POST /enroll-embedding} endpoint. Mirrors
     * {@link #enrollFace} but with the embedding already computed off-device.
     *
     * @param tenantId  optional tenant identifier — for pgvector tenant scoping
     *                  on the bio side (null/blank → bio default tenant)
     * @param userId    the user ID to enroll
     * @param embedding the 512-dim client-side embedding (list of floats)
     * @return Map containing enrollment response data (e.g. {@code success})
     */
    Map<String, Object> enrollEmbedding(String tenantId, UUID userId, List<Double> embedding);

    /**
     * Enrolls a user's voice in the biometric system.
     *
     * @param userId the user ID
     * @param voiceData the voice recording data (base64-encoded audio)
     * @return Map containing enrollment response data
     * @throws com.fivucsas.identity.domain.exception.BiometricEnrollmentException if enrollment fails
     */
    default Map<String, Object> enrollVoice(UUID userId, String voiceData) {
        return enrollVoice(userId, voiceData, false);
    }

    /**
     * Enrolls a user's voice, optionally as a "re-enroll &amp; optimize" — when
     * {@code optimize} is true and the user already has a voiceprint, the
     * biometric-processor FUSES this sample into the existing centroid. The flag
     * is forwarded to bio {@code /voice/enroll} as the {@code optimize} JSON
     * body field; an older bio build ignores it (graceful fallback).
     */
    Map<String, Object> enrollVoice(UUID userId, String voiceData, boolean optimize);

    /**
     * Verifies a user's voice against enrolled biometric data.
     *
     * @param userId the user ID
     * @param voiceData the voice recording data (base64-encoded audio)
     * @return Map containing verification response data
     */
    Map<String, Object> verifyVoice(UUID userId, String voiceData);

    /**
     * Deletes a user's enrolled face biometric data.
     *
     * @param userId the user ID
     * @return Map containing deletion response data
     */
    Map<String, Object> deleteFace(UUID userId);

    /**
     * Deletes a user's enrolled voice biometric data.
     *
     * @param userId the user ID
     * @return Map containing deletion response data
     */
    Map<String, Object> deleteVoice(UUID userId);

    /**
     * Searches for a face in the enrolled database (1:N identification).
     *
     * @param faceImage the face image to search
     * @return Map containing search results with matched user IDs and distances
     */
    default Map<String, Object> searchFace(MultipartFile faceImage) {
        return searchFace(faceImage, null, null, null);
    }

    /**
     * Searches for a face with tenant scoping (required by bio side as of
     * 2026-04 — defense-in-depth tenant isolation) and optional client
     * embedding telemetry.
     */
    Map<String, Object> searchFace(MultipartFile faceImage,
                                   String tenantId,
                                   String clientEmbedding,
                                   String clientEmbeddings);

    default Map<String, Object> enrollFaceMulti(UUID userId, List<MultipartFile> images) {
        return enrollFaceMulti(userId, images, null, null, null);
    }

    /**
     * Multi-image face enrollment with tenant scoping and optional client
     * embedding telemetry (D2 log-only).
     */
    default Map<String, Object> enrollFaceMulti(UUID userId,
                                                List<MultipartFile> images,
                                                String tenantId,
                                                String clientEmbedding,
                                                String clientEmbeddings) {
        return enrollFaceMulti(userId, images, tenantId, clientEmbedding, clientEmbeddings, false);
    }

    /**
     * Multi-image face enrollment, optionally as a "re-enroll &amp; optimize".
     * When {@code optimize} is true and the user already has a template, the
     * fused batch is in turn fused into the existing centroid (forwarded to bio
     * {@code /enroll/multi} as the {@code optimize} multipart field). When
     * false, behaviour is identical to the legacy multi-enroll.
     */
    Map<String, Object> enrollFaceMulti(UUID userId,
                                        List<MultipartFile> images,
                                        String tenantId,
                                        String clientEmbedding,
                                        String clientEmbeddings,
                                        boolean optimize);

    Map<String, Object> searchVoice(String voiceData);

    /**
     * Returns whether the bio face store actually holds a FACE embedding for the
     * given user under the given tenant.
     *
     * <p>This is the authoritative "is there really an enrollment?" check against
     * the embedding store (a SEPARATE database owned by the biometric-processor),
     * as opposed to the denormalized {@code users.is_biometric_enrolled} boolean
     * in identity_core. It backs the enrollment-flag reconciler
     * ({@code BiometricEnrollmentReconciler}) that repairs users who have a real
     * embedding but a stale {@code false} flag (the "enrolled-but-412" class).</p>
     *
     * <p><b>Fail-CLOSED:</b> any transport error, unreachable service, or
     * malformed response returns {@code false} — the reconciler must never flip a
     * flag to {@code true} on the basis of an unconfirmed enrollment. A
     * confirmed-absent embedding also returns {@code false}.</p>
     *
     * @param userId   the user to check
     * @param tenantId the tenant the embedding is scoped to (the bio store is
     *                 tenant-scoped); when null/blank the bio side falls back to
     *                 its default tenant
     * @return {@code true} only when an embedding for {@code userId} is confirmed
     *         present in {@code tenantId}; {@code false} otherwise (incl. errors)
     */
    boolean hasEnrollment(UUID userId, String tenantId);

    /**
     * Verifies the passive-authentication (chip-authenticity) of an eMRTD
     * (electronic passport / TR e-ID) by validating the {@code EF.SOD} →
     * Document Signer → CSCA certificate chain and that the supplied Data Group
     * hashes match those signed in the SOD.
     *
     * <p>This is the authoritative, server-side passive-auth verdict that gates
     * NFC enroll/verify (WS2). Clients may run an advisory client-side chain
     * check, but the api trusts only this result and is <b>fail-closed</b>: any
     * transport error, malformed response, or non-authentic verdict means the
     * chip is treated as NOT authentic.</p>
     *
     * <p>Delegates to the biometric-processor's CPU-only passive-auth endpoint
     * (X-API-Key authenticated). The request carries the base64-encoded SOD plus
     * whichever Data Groups the caller read from the chip (at minimum DG1; DG2
     * etc. are optional but strengthen the hash-binding check).</p>
     *
     * @param sodBase64 base64-encoded {@code EF.SOD} (required)
     * @param dataGroupsBase64 map of DG name → base64 DG bytes
     *                         (e.g. {@code {"dg1": "...", "dg2": "..."}}); may be
     *                         empty but at least DG1 is recommended
     * @return the raw verdict map from the biometric-processor; on transport
     *         failure a {@code {success=false, ...}} error map (callers must
     *         fail-closed)
     */
    Map<String, Object> verifyNfcChipAuthenticity(String sodBase64,
                                                  Map<String, String> dataGroupsBase64);

    /**
     * Generates a liveness puzzle challenge from the biometric processor.
     *
     * @param userId optional user identifier
     * @param difficulty puzzle difficulty (easy, standard, hard)
     * @return Map containing puzzle data (puzzle_id, steps, timeout, etc.)
     */
    Map<String, Object> generateLivenessPuzzle(String userId, String difficulty);

    /**
     * Verifies liveness puzzle completion with frame evidence.
     *
     * @param puzzleId the puzzle identifier to verify
     * @param frames the captured video frames as evidence
     * @return Map containing verification result (success, liveness_confirmed, score, etc.)
     */
    Map<String, Object> verifyLivenessPuzzle(String puzzleId, List<MultipartFile> frames);

    /**
     * Server-validates a single completed biometric-puzzle training challenge.
     *
     * <p>Thin proxy to the biometric-processor {@code POST /liveness/verify-challenge}
     * route (pure structural validation — action enum, timestamp monotonicity,
     * duration + confidence floors; no ML). Backs the {@code BiometricPuzzlesPage}
     * training surface so a completed challenge is not resolved purely
     * client-side.</p>
     *
     * <p><b>Graceful degradation:</b> this is a lightweight TRAINING surface, not
     * a security gate (the real liveness gate is enrollment/verify). If the bio
     * service is unreachable or returns 5xx, the implementation returns a
     * soft-pass verdict ({@code verified=true},
     * {@code reason_code=VALIDATION_UNAVAILABLE}) so the training UI never
     * hard-blocks on infrastructure. A genuine bio rejection
     * ({@code verified=false} with a reason) is forwarded faithfully.</p>
     *
     * @param request the challenge completion record (snake_case keys matching
     *                 the bio {@code VerifyChallengeRequest}: action,
     *                 start_timestamp_ms, end_timestamp_ms, confidence,
     *                 tenant_id, user_id, metrics)
     * @return Map containing the verdict (verified, action, duration_seconds,
     *         reason_code, message)
     */
    Map<String, Object> verifyPuzzleChallenge(Map<String, Object> request);
}
