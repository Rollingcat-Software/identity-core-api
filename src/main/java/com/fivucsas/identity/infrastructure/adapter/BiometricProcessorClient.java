package com.fivucsas.identity.infrastructure.adapter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Map;

/**
 * HTTP client for calling biometric-processor verification endpoints.
 * Separate from BiometricServiceAdapter to keep verification pipeline
 * concerns isolated from auth-time biometric operations.
 */
@Component
@Slf4j
public class BiometricProcessorClient {

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE =
            new ParameterizedTypeReference<>() {};

    private final RestClient restClient;

    public BiometricProcessorClient(
            RestClient.Builder restClientBuilder,
            @Value("${biometric.processor.url:${biometric.service.url:http://biometric-api:8001}}") String baseUrl,
            @Value("${biometric.service.api-key:}") String apiKey,
            @Value("${biometric.service.connect-timeout-ms:5000}") int connectTimeout,
            @Value("${biometric.service.read-timeout-ms:30000}") int readTimeout) {

        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(connectTimeout);
        requestFactory.setReadTimeout(readTimeout);

        RestClient.Builder builder = restClientBuilder
                .baseUrl(baseUrl)
                .requestFactory(requestFactory);
        if (apiKey != null && !apiKey.isBlank()) {
            builder = builder.defaultHeader("X-API-Key", apiKey);
        }
        this.restClient = builder.build();
        log.info("BiometricProcessorClient configured: baseUrl={}, connectTimeout={}ms, readTimeout={}ms",
                baseUrl, connectTimeout, readTimeout);
    }

    /**
     * Scan a document image and classify it.
     *
     * @param imageBase64 base64-encoded document image
     * @return response with document_type, confidence, etc.
     */
    public Map<String, Object> documentScan(String imageBase64) {
        log.info("Calling biometric-processor /api/v1/verification/document-scan");
        return postJson("/api/v1/verification/document-scan",
                Map.of("image", imageBase64));
    }

    /**
     * Extract personal data from a document image.
     *
     * @param imageBase64 base64-encoded document image
     * @return response with extracted fields (name, dob, document_number, etc.)
     */
    public Map<String, Object> dataExtract(String imageBase64) {
        log.info("Calling biometric-processor /api/v1/verification/data-extract");
        return postJson("/api/v1/verification/data-extract",
                Map.of("image", imageBase64));
    }

    /**
     * Compare a live face image against a document face photo.
     *
     * @param liveFaceBase64 base64-encoded live face image
     * @param docFaceBase64  base64-encoded face from document
     * @return response with match score and verified flag
     */
    public Map<String, Object> faceMatch(String liveFaceBase64, String docFaceBase64) {
        log.info("Calling biometric-processor /api/v1/verification/face-match");
        return postJson("/api/v1/verification/face-match",
                Map.of("live_face", liveFaceBase64, "document_face", docFaceBase64));
    }

    /**
     * Run liveness detection on a face image.
     *
     * @param imageBase64 base64-encoded face image
     * @return response with liveness_score and is_live flag
     */
    public Map<String, Object> livenessCheck(String imageBase64) {
        log.info("Calling biometric-processor /api/v1/verification/liveness-check");
        return postJson("/api/v1/verification/liveness-check",
                Map.of("image", imageBase64));
    }

    private Map<String, Object> postJson(String path, Map<String, String> body) {
        try {
            return restClient.post()
                    .uri(path)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(MAP_TYPE);
        } catch (HttpClientErrorException e) {
            log.warn("Biometric processor client error for {}: {} {}", path, e.getStatusCode(), e.getMessage());
            return errorResponse("Biometric processor rejected request: " + e.getResponseBodyAsString());
        } catch (HttpServerErrorException e) {
            log.error("Biometric processor server error for {}: {} {}", path, e.getStatusCode(), e.getMessage());
            return errorResponse("Biometric processor error, please retry");
        } catch (ResourceAccessException e) {
            log.error("Biometric processor unreachable for {}: {}", path, e.getMessage());
            return errorResponse("Biometric processor unavailable");
        } catch (RestClientException e) {
            log.error("Biometric processor communication error for {}: {}", path, e.getMessage());
            return errorResponse("Biometric processor communication error");
        }
    }

    private Map<String, Object> errorResponse(String message) {
        return Map.of("success", false, "error", message);
    }
}
