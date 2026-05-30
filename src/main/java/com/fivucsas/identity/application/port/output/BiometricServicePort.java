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
    Map<String, Object> enrollFace(UUID userId,
                                   MultipartFile faceImage,
                                   String tenantId,
                                   String clientEmbedding,
                                   String clientEmbeddings);

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
     * Enrolls a user's voice in the biometric system.
     *
     * @param userId the user ID
     * @param voiceData the voice recording data (base64-encoded audio)
     * @return Map containing enrollment response data
     * @throws com.fivucsas.identity.domain.exception.BiometricEnrollmentException if enrollment fails
     */
    Map<String, Object> enrollVoice(UUID userId, String voiceData);

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
    Map<String, Object> enrollFaceMulti(UUID userId,
                                        List<MultipartFile> images,
                                        String tenantId,
                                        String clientEmbedding,
                                        String clientEmbeddings);

    Map<String, Object> searchVoice(String voiceData);

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
}
