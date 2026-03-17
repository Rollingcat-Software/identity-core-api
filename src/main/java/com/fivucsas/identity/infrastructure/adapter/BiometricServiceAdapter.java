package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
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
            @Value("${biometric.service.api-key:}") String apiKey,
            @Value("${biometric.service.connect-timeout-ms:5000}") int connectTimeout,
            @Value("${biometric.service.read-timeout-ms:30000}") int readTimeout) {

        this.biometricServiceUrl = biometricServiceUrl;

        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(connectTimeout);
        requestFactory.setReadTimeout(readTimeout);

        RestClient.Builder builder = restClientBuilder
                .baseUrl(biometricServiceUrl)
                .requestFactory(requestFactory);
        if (apiKey != null && !apiKey.isBlank()) {
            builder = builder.defaultHeader("X-API-Key", apiKey);
            log.info("BiometricServiceAdapter configured with API key authentication");
        }
        this.restClient = builder.build();
        log.info("BiometricServiceAdapter configured with connectTimeout={}ms, readTimeout={}ms",
                connectTimeout, readTimeout);
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
        } catch (HttpClientErrorException e) {
            log.warn("Biometric service client error for enrollment: {} {}", e.getStatusCode(), e.getMessage());
            return errorResponse("Enrollment rejected: " + e.getResponseBodyAsString());
        } catch (HttpServerErrorException e) {
            log.error("Biometric service server error for enrollment: {} {}", e.getStatusCode(), e.getMessage());
            return errorResponse("Biometric service error, please retry");
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for enrollment: {}", e.getMessage());
            return errorResponse("Biometric service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service communication error for enrollment: {}", e.getMessage());
            return errorResponse("Biometric service communication error");
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
        } catch (HttpClientErrorException e) {
            log.warn("Biometric service client error for verification: {} {}", e.getStatusCode(), e.getMessage());
            return errorResponse("Verification rejected: " + e.getResponseBodyAsString());
        } catch (HttpServerErrorException e) {
            log.error("Biometric service server error for verification: {} {}", e.getStatusCode(), e.getMessage());
            return errorResponse("Biometric service error, please retry");
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for verification: {}", e.getMessage());
            return errorResponse("Biometric service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service communication error for verification: {}", e.getMessage());
            return errorResponse("Biometric service communication error");
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
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for fingerprint enrollment: {}", e.getMessage());
            return errorResponse("Fingerprint enrollment service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for fingerprint enrollment: {}", e.getMessage());
            return errorResponse("Fingerprint enrollment service error");
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
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for fingerprint verification: {}", e.getMessage());
            return errorResponse("Fingerprint verification service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for fingerprint verification: {}", e.getMessage());
            return errorResponse("Fingerprint verification service error");
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
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for voice enrollment: {}", e.getMessage());
            return errorResponse("Voice enrollment service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for voice enrollment: {}", e.getMessage());
            return errorResponse("Voice enrollment service error");
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
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for voice verification: {}", e.getMessage());
            return errorResponse("Voice verification service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for voice verification: {}", e.getMessage());
            return errorResponse("Voice verification service error");
        }
    }

    @Override
    public Map<String, Object> deleteFace(UUID userId) {
        log.info("Calling biometric service to delete face data for user: {}", userId);
        try {
            return deleteResource("/enroll/" + userId);
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for face deletion: {}", e.getMessage());
            return errorResponse("Face deletion service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for face deletion: {}", e.getMessage());
            return errorResponse("Face deletion service error");
        }
    }

    @Override
    public Map<String, Object> deleteFingerprint(UUID userId) {
        log.info("Calling biometric service to delete fingerprint data for user: {}", userId);
        try {
            return deleteResource("/fingerprint/" + userId);
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for fingerprint deletion: {}", e.getMessage());
            return errorResponse("Fingerprint deletion service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for fingerprint deletion: {}", e.getMessage());
            return errorResponse("Fingerprint deletion service error");
        }
    }

    @Override
    public Map<String, Object> deleteVoice(UUID userId) {
        log.info("Calling biometric service to delete voice data for user: {}", userId);
        try {
            return deleteResource("/voice/" + userId);
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for voice deletion: {}", e.getMessage());
            return errorResponse("Voice deletion service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for voice deletion: {}", e.getMessage());
            return errorResponse("Voice deletion service error");
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> searchFace(MultipartFile faceImage) {
        log.info("Calling biometric service to search face");
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", faceImage.getResource()).contentType(MediaType.IMAGE_JPEG);

            return postMultipart("/search", bodyBuilder.build());
        } catch (HttpClientErrorException e) {
            log.warn("Biometric service client error for search: {} {}", e.getStatusCode(), e.getMessage());
            return errorResponse("Search rejected: " + e.getResponseBodyAsString());
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for search: {}", e.getMessage());
            return errorResponse("Search service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for search: {}", e.getMessage());
            return errorResponse("Search service error");
        }
    }

    @Override
    public Map<String, Object> generateLivenessPuzzle(String userId, String difficulty) {
        log.info("Calling biometric service to generate liveness puzzle for user: {}", userId);
        try {
            Map<String, Object> requestBody = new java.util.HashMap<>();
            if (userId != null) requestBody.put("user_id", userId);
            if (difficulty != null) requestBody.put("difficulty", difficulty);
            else requestBody.put("difficulty", "standard");

            return restClient.post()
                    .uri("/liveness/generate-puzzle")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(requestBody)
                    .retrieve()
                    .body(MAP_TYPE);
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for liveness puzzle: {}", e.getMessage());
            return errorResponse("Liveness puzzle service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for liveness puzzle: {}", e.getMessage());
            return errorResponse("Liveness puzzle service error");
        }
    }

    @Override
    public Map<String, Object> verifyLivenessPuzzle(String puzzleId, java.util.List<MultipartFile> frames) {
        log.info("Calling biometric service to verify liveness puzzle: {} with {} frames", puzzleId, frames.size());
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("puzzle_id", puzzleId);
            for (int i = 0; i < frames.size(); i++) {
                bodyBuilder.part("frames", frames.get(i).getResource())
                        .contentType(MediaType.IMAGE_JPEG)
                        .filename("frame_" + i + ".jpg");
            }

            return restClient.post()
                    .uri("/liveness/verify")
                    .contentType(MediaType.MULTIPART_FORM_DATA)
                    .body(bodyBuilder.build())
                    .retrieve()
                    .body(MAP_TYPE);
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for liveness verification: {}", e.getMessage());
            return errorResponse("Liveness verification service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for liveness verification: {}", e.getMessage());
            return errorResponse("Liveness verification service error");
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
