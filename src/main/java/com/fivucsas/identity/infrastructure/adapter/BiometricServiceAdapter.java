package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

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
@Slf4j
public class BiometricServiceAdapter implements BiometricServicePort {

    private final WebClient webClient;
    private final String biometricServiceUrl;

    public BiometricServiceAdapter(
            WebClient.Builder webClientBuilder,
            @Value("${biometric.service.url}") String biometricServiceUrl,
            @Value("${biometric.service.api-key:}") String apiKey) {

        this.biometricServiceUrl = biometricServiceUrl;

        WebClient.Builder builder = webClientBuilder;
        if (apiKey != null && !apiKey.isBlank()) {
            builder = builder.defaultHeader("X-API-Key", apiKey);
            log.info("BiometricServiceAdapter configured with API key authentication");
        }
        this.webClient = builder.build();
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> enrollFace(UUID userId, MultipartFile faceImage) {
        log.info("Calling biometric service to enroll face for user: {}", userId);

        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", faceImage.getResource())
                .contentType(MediaType.IMAGE_JPEG);
            bodyBuilder.part("user_id", userId.toString());

            Map<String, Object> response = webClient
                .post()
                .uri(biometricServiceUrl + "/enroll")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(BodyInserters.fromMultipartData(bodyBuilder.build()))
                .exchangeToMono(clientResponse -> {
                    if (clientResponse.statusCode().is2xxSuccessful()) {
                        return clientResponse.bodyToMono(Map.class);
                    }
                    // Preserve error response body (e.g. SPOOF_DETECTED from 403)
                    return clientResponse.bodyToMono(Map.class)
                            .defaultIfEmpty(Map.of(
                                "error_code", "BIOMETRIC_ERROR",
                                "message", "Biometric service returned " + clientResponse.statusCode()
                            ));
                })
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

            Map<String, Object> response = webClient
                .post()
                .uri(biometricServiceUrl + "/verify")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(BodyInserters.fromMultipartData(bodyBuilder.build()))
                .exchangeToMono(clientResponse -> {
                    if (clientResponse.statusCode().is2xxSuccessful()) {
                        return clientResponse.bodyToMono(Map.class);
                    }
                    return clientResponse.bodyToMono(Map.class)
                            .defaultIfEmpty(Map.of(
                                "error_code", "BIOMETRIC_ERROR",
                                "message", "Biometric service returned " + clientResponse.statusCode()
                            ));
                })
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

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> verifyFingerprint(UUID userId, String fingerprintData) {
        log.info("Calling biometric service to verify fingerprint for user: {}", userId);

        try {
            Map<String, String> body = Map.of(
                "user_id", userId.toString(),
                "fingerprint_data", fingerprintData
            );

            Map<String, Object> response = webClient
                .post()
                .uri(biometricServiceUrl + "/fingerprint/verify")
                .bodyValue(body)
                .exchangeToMono(clientResponse -> {
                    if (clientResponse.statusCode().is2xxSuccessful()) {
                        return clientResponse.bodyToMono(Map.class);
                    }
                    return clientResponse.bodyToMono(Map.class)
                            .defaultIfEmpty(Map.of(
                                "error_code", "BIOMETRIC_ERROR",
                                "message", "Biometric service returned " + clientResponse.statusCode()
                            ));
                })
                .block();

            log.info("Fingerprint verification response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for fingerprint verification: {}", e.getMessage());
            return Map.of(
                "success", false,
                "message", "Fingerprint verification service unavailable: " + e.getMessage()
            );
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> verifyVoice(UUID userId, String voiceData) {
        log.info("Calling biometric service to verify voice for user: {}", userId);

        try {
            Map<String, String> body = Map.of(
                "user_id", userId.toString(),
                "voice_data", voiceData
            );

            Map<String, Object> response = webClient
                .post()
                .uri(biometricServiceUrl + "/voice/verify")
                .bodyValue(body)
                .exchangeToMono(clientResponse -> {
                    if (clientResponse.statusCode().is2xxSuccessful()) {
                        return clientResponse.bodyToMono(Map.class);
                    }
                    return clientResponse.bodyToMono(Map.class)
                            .defaultIfEmpty(Map.of(
                                "error_code", "BIOMETRIC_ERROR",
                                "message", "Biometric service returned " + clientResponse.statusCode()
                            ));
                })
                .block();

            log.info("Voice verification response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for voice verification: {}", e.getMessage());
            return Map.of(
                "success", false,
                "message", "Voice verification service unavailable: " + e.getMessage()
            );
        }
    }
}
