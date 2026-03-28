package com.fivucsas.identity.infrastructure.adapter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Base64;
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
     * Biometric-processor expects multipart file upload (UploadFile).
     *
     * @param imageBase64 base64-encoded document image
     * @return response with document_type, confidence, etc.
     */
    public Map<String, Object> documentScan(String imageBase64) {
        log.info("Calling biometric-processor /api/v1/verification/document-scan");
        return postMultipartFile("/api/v1/verification/document-scan", "file", imageBase64);
    }

    /**
     * Extract personal data from a document image or MRZ text.
     * Biometric-processor accepts Form(image_base64) or Form(mrz_text).
     *
     * @param imageBase64 base64-encoded document image
     * @return response with extracted fields (name, dob, document_number, etc.)
     */
    public Map<String, Object> dataExtract(String imageBase64) {
        log.info("Calling biometric-processor /api/v1/verification/data-extract");
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("image_base64", imageBase64);
        return postFormData("/api/v1/verification/data-extract", formData);
    }

    /**
     * Extract personal data from MRZ text directly.
     * Biometric-processor accepts Form(mrz_text).
     *
     * @param mrzText raw MRZ text (2-3 lines separated by newline)
     * @return response with extracted fields
     */
    public Map<String, Object> dataExtractMrz(String mrzText) {
        log.info("Calling biometric-processor /api/v1/verification/data-extract (MRZ)");
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("mrz_text", mrzText);
        return postFormData("/api/v1/verification/data-extract", formData);
    }

    /**
     * Compare a live face image against a document face photo.
     * Biometric-processor expects Form(live_face_image) and Form(document_face_image).
     *
     * @param liveFaceBase64 base64-encoded live face image
     * @param docFaceBase64  base64-encoded face from document
     * @return response with match score and verified flag
     */
    public Map<String, Object> faceMatch(String liveFaceBase64, String docFaceBase64) {
        log.info("Calling biometric-processor /api/v1/verification/face-match");
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("live_face_image", liveFaceBase64);
        formData.add("document_face_image", docFaceBase64);
        return postFormData("/api/v1/verification/face-match", formData);
    }

    /**
     * Run liveness detection on a face image.
     * Biometric-processor expects multipart file upload (UploadFile).
     *
     * @param imageBase64 base64-encoded face image
     * @return response with liveness_score and is_live flag
     */
    public Map<String, Object> livenessCheck(String imageBase64) {
        log.info("Calling biometric-processor /api/v1/verification/liveness-check");
        return postMultipartFile("/api/v1/verification/liveness-check", "file", imageBase64);
    }

    /**
     * Post a base64 image as a multipart file upload.
     * Decodes the base64 string and sends it as a file part.
     */
    private Map<String, Object> postMultipartFile(String path, String fieldName, String imageBase64) {
        try {
            byte[] imageBytes = Base64.getDecoder().decode(stripDataUriPrefix(imageBase64));
            ByteArrayResource resource = new ByteArrayResource(imageBytes) {
                @Override
                public String getFilename() {
                    return "image.jpg";
                }
            };

            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add(fieldName, resource);

            return restClient.post()
                    .uri(path)
                    .contentType(MediaType.MULTIPART_FORM_DATA)
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
        } catch (IllegalArgumentException e) {
            log.warn("Invalid base64 data for {}: {}", path, e.getMessage());
            return errorResponse("Invalid base64 image data");
        }
    }

    /**
     * Post form-encoded data (for endpoints that accept Form fields).
     */
    private Map<String, Object> postFormData(String path, MultiValueMap<String, String> formData) {
        try {
            return restClient.post()
                    .uri(path)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(formData)
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

    /**
     * Strip data URI prefix (e.g., "data:image/jpeg;base64,") from a base64 string.
     */
    private String stripDataUriPrefix(String base64) {
        if (base64 != null && base64.contains(",")) {
            return base64.substring(base64.indexOf(",") + 1);
        }
        return base64;
    }

    private Map<String, Object> errorResponse(String message) {
        return Map.of("success", false, "error", message);
    }
}
