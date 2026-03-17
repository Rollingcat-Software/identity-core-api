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
     * Enrolls a user's face in the biometric system.
     *
     * @param userId the user ID
     * @param faceImage the face image file
     * @return Map containing enrollment response data
     * @throws com.fivucsas.identity.domain.exception.BiometricEnrollmentException if enrollment fails
     */
    Map<String, Object> enrollFace(UUID userId, MultipartFile faceImage);

    /**
     * Verifies a user's face against enrolled biometric data.
     *
     * @param userId the user ID
     * @param faceImage the face image file to verify
     * @return Map containing verification response data
     * @throws com.fivucsas.identity.domain.exception.BiometricVerificationException if verification fails
     */
    Map<String, Object> verifyFace(UUID userId, MultipartFile faceImage);

    /**
     * Enrolls a user's fingerprint in the biometric system.
     *
     * @param userId the user ID
     * @param fingerprintData the fingerprint data (base64-encoded template)
     * @return Map containing enrollment response data
     * @throws com.fivucsas.identity.domain.exception.BiometricEnrollmentException if enrollment fails
     */
    Map<String, Object> enrollFingerprint(UUID userId, String fingerprintData);

    /**
     * Verifies a user's fingerprint against enrolled biometric data.
     *
     * @param userId the user ID
     * @param fingerprintData the fingerprint data (base64-encoded template)
     * @return Map containing verification response data
     */
    Map<String, Object> verifyFingerprint(UUID userId, String fingerprintData);

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
     * Deletes a user's enrolled fingerprint biometric data.
     *
     * @param userId the user ID
     * @return Map containing deletion response data
     */
    Map<String, Object> deleteFingerprint(UUID userId);

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
    Map<String, Object> searchFace(MultipartFile faceImage);

    Map<String, Object> searchVoice(String voiceData);

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
