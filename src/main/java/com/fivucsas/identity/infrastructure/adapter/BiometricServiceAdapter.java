package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;
import java.util.UUID;

/**
 * Infrastructure adapter for biometric service.
 *
 * Implements the BiometricServicePort by calling the external FastAPI service.
 * Uses Spring 6's RestClient (synchronous) instead of reactive WebClient
 * since all calls were blocking anyway.
 */
@Component
@Slf4j
public class BiometricServiceAdapter implements BiometricServicePort {

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE =
            new ParameterizedTypeReference<>() {};

    private final RestClient restClient;
    private final String biometricServiceUrl;

    public BiometricServiceAdapter(
            RestClient.Builder restClientBuilder,
            @Value("${biometric.service.url}") String biometricServiceUrl,
            @Value("${biometric.service.api-key:}") String apiKey) {

        this.biometricServiceUrl = biometricServiceUrl;

        RestClient.Builder builder = restClientBuilder.baseUrl(biometricServiceUrl);
        if (apiKey != null && !apiKey.isBlank()) {
            builder = builder.defaultHeader("X-API-Key", apiKey);
            log.info("BiometricServiceAdapter configured with API key authentication");
        }
        this.restClient = builder.build();
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> enrollFace(UUID userId, MultipartFile faceImage) {
        log.info("Calling biometric service to enroll face for user: {}", userId);
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", faceImage.getResource()).contentType(MediaType.IMAGE_JPEG);
            bodyBuilder.part("user_id", userId.toString());

            Map<String, Object> response = postMultipart("/enroll", bodyBuilder.build());
            log.info("Biometric enrollment response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for enrollment: {}", e.getMessage());
            return errorResponse("Biometric service unavailable: " + e.getMessage());
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> verifyFace(UUID userId, MultipartFile faceImage) {
        log.info("Calling biometric service to verify face for user: {}", userId);
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", faceImage.getResource()).contentType(MediaType.IMAGE_JPEG);
            bodyBuilder.part("user_id", userId.toString());

            Map<String, Object> response = postMultipart("/verify", bodyBuilder.build());
            log.info("Biometric verification response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for verification: {}", e.getMessage());
            return errorResponse("Biometric service unavailable: " + e.getMessage());
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> enrollFingerprint(UUID userId, String fingerprintData) {
        log.info("Calling biometric service to enroll fingerprint for user: {}", userId);
        try {
            Map<String, Object> response = postJson("/fingerprint/enroll",
                    Map.of("user_id", userId.toString(), "fingerprint_data", fingerprintData));
            log.info("Fingerprint enrollment response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for fingerprint enrollment: {}", e.getMessage());
            return errorResponse("Fingerprint enrollment service unavailable: " + e.getMessage());
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> verifyFingerprint(UUID userId, String fingerprintData) {
        log.info("Calling biometric service to verify fingerprint for user: {}", userId);
        try {
            Map<String, Object> response = postJson("/fingerprint/verify",
                    Map.of("user_id", userId.toString(), "fingerprint_data", fingerprintData));
            log.info("Fingerprint verification response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for fingerprint verification: {}", e.getMessage());
            return errorResponse("Fingerprint verification service unavailable: " + e.getMessage());
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> enrollVoice(UUID userId, String voiceData) {
        log.info("Calling biometric service to enroll voice for user: {}", userId);
        try {
            Map<String, Object> response = postJson("/voice/enroll",
                    Map.of("user_id", userId.toString(), "voice_data", voiceData));
            log.info("Voice enrollment response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for voice enrollment: {}", e.getMessage());
            return errorResponse("Voice enrollment service unavailable: " + e.getMessage());
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> verifyVoice(UUID userId, String voiceData) {
        log.info("Calling biometric service to verify voice for user: {}", userId);
        try {
            Map<String, Object> response = postJson("/voice/verify",
                    Map.of("user_id", userId.toString(), "voice_data", voiceData));
            log.info("Voice verification response received for user: {}", userId);
            return response;
        } catch (Exception e) {
            log.error("Error calling biometric service for voice verification: {}", e.getMessage());
            return errorResponse("Voice verification service unavailable: " + e.getMessage());
        }
    }

    @Override
    public Map<String, Object> deleteFace(UUID userId) {
        log.info("Calling biometric service to delete face data for user: {}", userId);
        try {
            return deleteResource("/enroll/" + userId);
        } catch (Exception e) {
            log.error("Error calling biometric service for face deletion: {}", e.getMessage());
            return errorResponse("Face deletion service unavailable: " + e.getMessage());
        }
    }

    @Override
    public Map<String, Object> deleteFingerprint(UUID userId) {
        log.info("Calling biometric service to delete fingerprint data for user: {}", userId);
        try {
            return deleteResource("/fingerprint/enroll/" + userId);
        } catch (Exception e) {
            log.error("Error calling biometric service for fingerprint deletion: {}", e.getMessage());
            return errorResponse("Fingerprint deletion service unavailable: " + e.getMessage());
        }
    }

    @Override
    public Map<String, Object> deleteVoice(UUID userId) {
        log.info("Calling biometric service to delete voice data for user: {}", userId);
        try {
            return deleteResource("/voice/enroll/" + userId);
        } catch (Exception e) {
            log.error("Error calling biometric service for voice deletion: {}", e.getMessage());
            return errorResponse("Voice deletion service unavailable: " + e.getMessage());
        }
    }

    private Map<String, Object> deleteResource(String path) {
        return restClient.delete()
                .uri(path)
                .retrieve()
                .body(MAP_TYPE);
    }

    private Map<String, Object> postMultipart(String path, MultiValueMap<String, org.springframework.http.HttpEntity<?>> parts) {
        return restClient.post()
                .uri(path)
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(parts)
                .retrieve()
                .body(MAP_TYPE);
    }

    private Map<String, Object> postJson(String path, Map<String, String> body) {
        return restClient.post()
                .uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .body(MAP_TYPE);
    }

    private Map<String, Object> errorResponse(String message) {
        return Map.of("success", false, "message", message);
    }
}
