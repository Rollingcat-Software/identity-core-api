package com.fivucsas.identity.application.port.output;

import org.springframework.web.multipart.MultipartFile;

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
}
