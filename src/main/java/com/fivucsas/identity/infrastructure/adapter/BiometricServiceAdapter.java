package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;
import java.util.UUID;

/**
 * Infrastructure adapter for biometric service.
 *
 * Implements the BiometricServicePort by calling the external FastAPI service.
 * This adapter bridges the application layer with the external biometric service.
 *
 * Following principles:
 * - Adapter Pattern: Adapts external service to our port
 * - Dependency Inversion: Application defines port, infrastructure implements
 * - Abstraction: Hides external service details from application
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class BiometricServiceAdapter implements BiometricServicePort {

    private final WebClient.Builder webClientBuilder;

    @Value("${biometric.service.url}")
    private String biometricServiceUrl;

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> enrollFace(UUID userId, MultipartFile faceImage) {
        log.info("Calling biometric service to enroll face for user: {}", userId);

        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", faceImage.getResource())
                .contentType(MediaType.IMAGE_JPEG);
            bodyBuilder.part("user_id", userId.toString());

            Map<String, Object> response = webClientBuilder.build()
                .post()
                .uri(biometricServiceUrl + "/enroll")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(BodyInserters.fromMultipartData(bodyBuilder.build()))
                .retrieve()
                .bodyToMono(Map.class)
                .block();

            log.info("Biometric enrollment response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for enrollment: {}", e.getMessage());
            return Map.of(
                "success", false,
                "message", "Biometric service unavailable: " + e.getMessage()
            );
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> verifyFace(UUID userId, MultipartFile faceImage) {
        log.info("Calling biometric service to verify face for user: {}", userId);

        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", faceImage.getResource())
                .contentType(MediaType.IMAGE_JPEG);
            bodyBuilder.part("user_id", userId.toString());

            Map<String, Object> response = webClientBuilder.build()
                .post()
                .uri(biometricServiceUrl + "/verify")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(BodyInserters.fromMultipartData(bodyBuilder.build()))
                .retrieve()
                .bodyToMono(Map.class)
                .block();

            log.info("Biometric verification response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for verification: {}", e.getMessage());
            return Map.of(
                "success", false,
                "message", "Biometric service unavailable: " + e.getMessage()
            );
        }
    }
}
