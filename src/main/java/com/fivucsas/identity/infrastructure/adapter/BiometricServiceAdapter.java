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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Infrastructure adapter for biometric service.
 *
 * Implements the BiometricServicePort by calling the external FastAPI service.
 * Uses Spring 6's RestClient (synchronous) instead of reactive WebClient
 * since all calls were blocking anyway.
 *
 * <p>Typing note: every response is deserialised through
 * {@link #MAP_TYPE} (a {@link ParameterizedTypeReference}). RestClient
 * preserves the parameterised return type, so no unchecked cast is performed
 * inside this class — the {@code @SuppressWarnings("unchecked")} annotations
 * that previously sat on each {@code Map<String, Object>}-returning method
 * were therefore noise and were removed in the P1-Q6 quality batch
 * (review 2026-05-01). A future change that introduces typed Jackson DTOs
 * per Python endpoint (BiometricEnrollResponse, BiometricVerifyResponse, …)
 * would let callers stop reasoning about loose maps; that work is tracked
 * separately and is out of scope here.</p>
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
    public Map<String, Object> checkHealth() {
        log.debug("Checking biometric service health");
        try {
            Map<String, Object> response = restClient.get()
                    .uri("/health")
                    .retrieve()
                    .body(MAP_TYPE);
            log.debug("Biometric service health check response: {}", response);
            return response;
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for health check: {}", e.getMessage());
            return errorResponse("Biometric service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for health check: {}", e.getMessage());
            return errorResponse("Biometric service health check failed");
        }
    }

    @Override
    public Map<String, Object> enrollFace(UUID userId,
                                          MultipartFile faceImage,
                                          String tenantId,
                                          String clientEmbedding,
                                          String clientEmbeddings,
                                          boolean optimize) {
        log.info("Calling biometric service to enroll face for user: {} (tenant: {}, optimize: {})",
                userId, tenantId, optimize);
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", faceImage.getResource()).contentType(MediaType.IMAGE_JPEG);
            bodyBuilder.part("user_id", userId.toString());
            addOptionalTenantAndEmbeddingParts(bodyBuilder, tenantId, clientEmbedding, clientEmbeddings);
            if (optimize) {
                bodyBuilder.part("optimize", "true");
            }

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
    public Map<String, Object> verifyFace(UUID userId,
                                          MultipartFile faceImage,
                                          String tenantId,
                                          String clientEmbedding,
                                          String clientEmbeddings) {
        log.info("Calling biometric service to verify face for user: {} (tenant: {})", userId, tenantId);
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", faceImage.getResource()).contentType(MediaType.IMAGE_JPEG);
            bodyBuilder.part("user_id", userId.toString());
            addOptionalTenantAndEmbeddingParts(bodyBuilder, tenantId, clientEmbedding, clientEmbeddings);

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
    public Map<String, Object> verifyEmbedding(String tenantId, UUID userId, List<Double> embedding) {
        log.info("Calling biometric service to verify embedding for user: {} (tenant: {})", userId, tenantId);
        try {
            Map<String, Object> response = postJsonObject("/verify-embedding",
                    embeddingBody(tenantId, userId, embedding));
            log.info("Biometric embedding verification response received for user: {}", userId);
            return response;
        } catch (HttpClientErrorException e) {
            log.warn("Biometric service client error for embedding verification: {} {}", e.getStatusCode(), e.getMessage());
            return errorResponse("Verification rejected: " + e.getResponseBodyAsString());
        } catch (HttpServerErrorException e) {
            log.error("Biometric service server error for embedding verification: {} {}", e.getStatusCode(), e.getMessage());
            return errorResponse("Biometric service error, please retry");
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for embedding verification: {}", e.getMessage());
            return errorResponse("Biometric service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service communication error for embedding verification: {}", e.getMessage());
            return errorResponse("Biometric service communication error");
        }
    }

    @Override
    public Map<String, Object> enrollEmbedding(String tenantId, UUID userId, List<Double> embedding) {
        log.info("Calling biometric service to enroll embedding for user: {} (tenant: {})", userId, tenantId);
        try {
            Map<String, Object> response = postJsonObject("/enroll-embedding",
                    embeddingBody(tenantId, userId, embedding));
            log.info("Biometric embedding enrollment response received for user: {}", userId);
            return response;
        } catch (HttpClientErrorException e) {
            log.warn("Biometric service client error for embedding enrollment: {} {}", e.getStatusCode(), e.getMessage());
            return errorResponse("Enrollment rejected: " + e.getResponseBodyAsString());
        } catch (HttpServerErrorException e) {
            log.error("Biometric service server error for embedding enrollment: {} {}", e.getStatusCode(), e.getMessage());
            return errorResponse("Biometric service error, please retry");
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for embedding enrollment: {}", e.getMessage());
            return errorResponse("Biometric service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service communication error for embedding enrollment: {}", e.getMessage());
            return errorResponse("Biometric service communication error");
        }
    }

    /**
     * Builds the JSON body for the embedding enroll/verify endpoints:
     * {@code {user_id, embedding:[...], tenant_id?}}. The {@code tenant_id} part
     * is forwarded only when present (pgvector tenant scoping), mirroring the
     * multipart {@code addOptionalTenantAndEmbeddingParts} contract for the image
     * endpoints.
     */
    private static Map<String, Object> embeddingBody(String tenantId, UUID userId, List<Double> embedding) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        // userId is always non-null at the call sites (user.getId() /
        // UUID.fromString of a resolved user) — fail loud rather than POST a
        // {"user_id": null} the bio side would 422 on.
        body.put("user_id", java.util.Objects.requireNonNull(userId, "userId").toString());
        body.put("embedding", embedding);
        if (tenantId != null && !tenantId.isBlank()) {
            body.put("tenant_id", tenantId);
        }
        return body;
    }

    @Override
    public Map<String, Object> enrollVoice(UUID userId, String voiceData, boolean optimize) {
        log.info("Calling biometric service to enroll voice for user: {} (optimize: {})", userId, optimize);
        try {
            // postJsonObject (not postJson) so `optimize` serializes as a real
            // JSON boolean (the bio VoiceRequest.optimize field is typed bool).
            Map<String, Object> body = new java.util.LinkedHashMap<>();
            body.put("user_id", userId.toString());
            body.put("voice_data", voiceData);
            body.put("optimize", optimize);
            Map<String, Object> response = postJsonObject("/voice/enroll", body);
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
    public Map<String, Object> enrollFaceMulti(UUID userId,
                                               List<MultipartFile> images,
                                               String tenantId,
                                               String clientEmbedding,
                                               String clientEmbeddings,
                                               boolean optimize) {
        log.info("Calling biometric service for multi-image enrollment: userId={}, images={}, tenant={}, optimize={}",
                userId, images.size(), tenantId, optimize);
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("user_id", userId.toString());
            for (int i = 0; i < images.size(); i++) {
                MultipartFile img = images.get(i);
                String filename = img.getOriginalFilename() != null ? img.getOriginalFilename() : "face_" + i + ".jpg";
                bodyBuilder.part("files", img.getResource())
                        .contentType(MediaType.IMAGE_JPEG)
                        .filename(filename);
            }
            addOptionalTenantAndEmbeddingParts(bodyBuilder, tenantId, clientEmbedding, clientEmbeddings);
            if (optimize) {
                bodyBuilder.part("optimize", "true");
            }
            return postMultipart("/enroll/multi", bodyBuilder.build());
        } catch (HttpClientErrorException e) {
            return errorResponse("Multi-enrollment rejected: " + e.getResponseBodyAsString());
        } catch (ResourceAccessException e) {
            return errorResponse("Biometric service unavailable");
        } catch (RestClientException e) {
            return errorResponse("Biometric service error");
        }
    }

    @Override
    public Map<String, Object> searchFace(MultipartFile faceImage,
                                          String tenantId,
                                          String clientEmbedding,
                                          String clientEmbeddings) {
        log.info("Calling biometric service to search face (tenant: {})", tenantId);
        try {
            MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
            bodyBuilder.part("file", faceImage.getResource()).contentType(MediaType.IMAGE_JPEG);
            addOptionalTenantAndEmbeddingParts(bodyBuilder, tenantId, clientEmbedding, clientEmbeddings);

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

    /**
     * Forwards optional tenant_id, client_embedding and client_embeddings
     * multipart parts when present. Kept centralized so all four face
     * endpoints (/enroll, /enroll/multi, /verify, /search) share identical
     * forwarding behavior.
     *
     * <p>Background: 2026-04-28 web-app reroute (Sec-P0b) eliminated
     * VITE_BIOMETRIC_API_KEY from the SPA, routing all browser-originated
     * face calls through this proxy. Without forwarding {@code tenant_id} the
     * bio side cannot scope pgvector queries; without forwarding
     * {@code client_embedding(s)} the D2 log-only telemetry channel is
     * silently dropped.</p>
     */
    private void addOptionalTenantAndEmbeddingParts(MultipartBodyBuilder bodyBuilder,
                                                    String tenantId,
                                                    String clientEmbedding,
                                                    String clientEmbeddings) {
        if (tenantId != null && !tenantId.isBlank()) {
            bodyBuilder.part("tenant_id", tenantId);
        }
        if (clientEmbedding != null && !clientEmbedding.isBlank()) {
            bodyBuilder.part("client_embedding", clientEmbedding);
        }
        if (clientEmbeddings != null && !clientEmbeddings.isBlank()) {
            bodyBuilder.part("client_embeddings", clientEmbeddings);
        }
    }

    @Override
    public Boolean voiceEnrollmentExists(UUID userId) {
        if (userId == null) {
            return Boolean.FALSE;
        }
        // bio GET /voice/{userId}/exists → {user_id, exists}. Tri-state:
        // definitive 200 → TRUE/FALSE; outage (transport / 5xx / malformed) →
        // null so the caller can fail-OPEN on a bio outage (login triage F2/F7).
        return enrollmentExistsProbe("/voice/" + userId + "/exists", "voice", userId);
    }

    @Override
    public Boolean faceEnrollmentExists(UUID userId, String tenantId) {
        if (userId == null) {
            return Boolean.FALSE;
        }
        // bio GET /face/{userId}/exists?tenant_id=... → {user_id, exists}.
        // Same tri-state contract as the voice probe (login triage F9).
        String path = (tenantId != null && !tenantId.isBlank())
                ? "/face/" + userId + "/exists?tenant_id="
                        + java.net.URLEncoder.encode(tenantId, java.nio.charset.StandardCharsets.UTF_8)
                : "/face/" + userId + "/exists";
        return enrollmentExistsProbe(path, "face", userId);
    }

    /**
     * Shared GET probe for the {@code /voice|/face/{userId}/exists} endpoints.
     * Returns the {@code exists} boolean from a definitive 200, or {@code null}
     * (UNKNOWN) on any failure that means the bio service could not give a
     * definitive answer (unreachable, 5xx, or malformed/missing field) — letting
     * the caller fail-OPEN on a bio outage rather than lock users out. A 4xx is
     * treated as UNKNOWN too (the service is up but rejected the probe — a
     * contract anomaly, not a confirmation of absence), logged loudly.
     */
    private Boolean enrollmentExistsProbe(String path, String modality, UUID userId) {
        try {
            Map<String, Object> response = restClient.get()
                    .uri(path)
                    .retrieve()
                    .body(MAP_TYPE);
            if (response == null || !(response.get("exists") instanceof Boolean exists)) {
                log.warn("Bio {} existence probe for user {} returned no usable 'exists' field — treating as UNKNOWN",
                        modality, userId);
                return null;
            }
            return exists;
        } catch (HttpServerErrorException e) {
            log.warn("Bio {} existence probe 5xx for user {} — failing open (UNKNOWN): {} {}",
                    modality, userId, e.getStatusCode(), e.getMessage());
            return null;
        } catch (ResourceAccessException e) {
            log.warn("Bio {} existence probe unreachable for user {} — failing open (UNKNOWN): {}",
                    modality, userId, e.getMessage());
            return null;
        } catch (HttpClientErrorException e) {
            // Service is up but rejected our probe (e.g. 400 on a malformed id).
            // Not an outage and not a confirmation of absence — UNKNOWN, logged.
            log.warn("Bio {} existence probe rejected (4xx) for user {} — treating as UNKNOWN: {} {}",
                    modality, userId, e.getStatusCode(), e.getMessage());
            return null;
        } catch (RestClientException e) {
            log.warn("Bio {} existence probe communication error for user {} — failing open (UNKNOWN): {}",
                    modality, userId, e.getMessage());
            return null;
        }
    }

    @Override
    public boolean hasEnrollment(UUID userId, String tenantId) {
        if (userId == null) {
            return false;
        }
        // Backed by the bio service's existing /embeddings/export capability,
        // which lists the user_ids enrolled under a tenant. We do NOT add a new
        // bio endpoint here; the reconciler can also batch-list a whole tenant in
        // one call via exportEnrolledUserIds(tenantId) below. Fail-CLOSED: any
        // transport / shape problem yields false so a flag is never flipped on an
        // unconfirmed enrollment.
        try {
            Set<String> enrolled = exportEnrolledUserIds(tenantId);
            return enrolled.contains(userId.toString());
        } catch (Exception e) {
            log.warn("hasEnrollment check failed for user {} (tenant {}) — failing closed: {}",
                    userId, tenantId, e.getMessage());
            return false;
        }
    }

    /**
     * Lists the set of user_ids that actually have a FACE embedding under the
     * given tenant, via the bio {@code GET /embeddings/export} endpoint. Returns
     * an empty set on any error (fail-closed). Exposed package-internally so the
     * reconciler can list a whole tenant in ONE round-trip instead of one
     * {@link #hasEnrollment} call per candidate user.
     */
    Set<String> exportEnrolledUserIds(String tenantId) {
        String tenant = (tenantId != null && !tenantId.isBlank()) ? tenantId : "default";
        Map<String, Object> response = restClient.get()
                .uri(uriBuilder -> uriBuilder.path("/embeddings/export")
                        .queryParam("tenant_id", tenant)
                        .queryParam("include_metadata", false)
                        .build())
                .retrieve()
                .body(MAP_TYPE);
        Set<String> userIds = new HashSet<>();
        if (response == null) {
            return userIds;
        }
        Object embeddings = response.get("embeddings");
        if (embeddings instanceof List<?> list) {
            for (Object row : list) {
                if (row instanceof Map<?, ?> rowMap) {
                    Object uid = rowMap.get("user_id");
                    if (uid == null) {
                        uid = rowMap.get("id");
                    }
                    if (uid != null) {
                        userIds.add(String.valueOf(uid));
                    }
                }
            }
        }
        return userIds;
    }

    @Override
    public Map<String, Object> searchVoice(String voiceData) {
        log.info("Calling biometric service to search voice");
        try {
            return postJson("/voice/search", Map.of("voice_data", voiceData));
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for voice search: {}", e.getMessage());
            return errorResponse("Voice search service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for voice search: {}", e.getMessage());
            return errorResponse("Voice search service error");
        }
    }

    @Override
    public Map<String, Object> verifyNfcChipAuthenticity(String sodBase64,
                                                         Map<String, String> dataGroupsBase64) {
        log.info("Calling biometric service /api/v1/nfc/verify-authenticity ({} data groups)",
                dataGroupsBase64 != null ? dataGroupsBase64.size() : 0);
        // Frozen contract (agent-bio PR #131):
        //   { "sod_b64": "<b64 EF.SOD DER>",
        //     "data_groups": { "1": "<b64>", "2": "<b64>", ... } }
        // DG keys are the stringified DG NUMBER ("1".."16"). Callers may pass
        // either "1" or "dg1" — both normalize to the bare number here.
        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("sod_b64", sodBase64);
        java.util.Map<String, String> dataGroups = new java.util.LinkedHashMap<>();
        if (dataGroupsBase64 != null) {
            for (Map.Entry<String, String> dg : dataGroupsBase64.entrySet()) {
                if (dg.getKey() == null || dg.getValue() == null || dg.getValue().isBlank()) {
                    continue;
                }
                String num = dg.getKey().toLowerCase(java.util.Locale.ROOT).replaceFirst("^dg", "").trim();
                dataGroups.put(num, dg.getValue());
            }
        }
        // Bio requires >= 1 DG (an empty data_groups is a hard 400 there, and a
        // SOD with no DG to hash can't establish integrity anyway). Short-circuit
        // to a clean fail-closed verdict instead of a doomed 400 round-trip; the
        // verdict interpreter maps reason_code=MISSING_DG → not authentic.
        if (dataGroups.isEmpty()) {
            log.warn("NFC chip-authenticity called with no data groups — failing closed (MISSING_DG)");
            return Map.of(
                    "is_authentic", false,
                    "reason", "At least one Data Group (e.g. DG1) is required for passive authentication",
                    "reason_code", "MISSING_DG");
        }
        body.put("data_groups", dataGroups);
        try {
            return postJsonObject("/api/v1/nfc/verify-authenticity", body);
        } catch (HttpClientErrorException e) {
            // Bio rejected the input (malformed SOD/DG, 4xx). Fail-closed: this
            // is an authenticity FAILURE, not an availability problem.
            log.warn("NFC chip-authenticity rejected by biometric service: {} {}",
                    e.getStatusCode(), e.getMessage());
            return errorResponse("NFC chip authenticity check rejected: " + e.getResponseBodyAsString());
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for NFC chip-authenticity: {}", e.getMessage());
            return errorResponse("NFC authenticity service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for NFC chip-authenticity: {}", e.getMessage());
            return errorResponse("NFC authenticity service error");
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
            // Convert frames to base64 for spot_frames field
            java.util.List<String> spotFrames = new java.util.ArrayList<>();
            for (MultipartFile frame : frames) {
                if (frame != null && !frame.isEmpty()) {
                    spotFrames.add(java.util.Base64.getEncoder().encodeToString(frame.getBytes()));
                }
            }

            // Build JSON body matching VerifyPuzzleRequest schema
            Map<String, Object> requestBody = new java.util.HashMap<>();
            requestBody.put("puzzle_id", puzzleId);
            requestBody.put("results", java.util.Collections.emptyList());
            requestBody.put("spot_frames", spotFrames);

            return restClient.post()
                    .uri("/liveness/verify")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(requestBody)
                    .retrieve()
                    .body(MAP_TYPE);
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for liveness verification: {}", e.getMessage());
            return errorResponse("Liveness verification service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for liveness verification: {}", e.getMessage());
            return errorResponse("Liveness verification service error");
        } catch (java.io.IOException e) {
            log.error("Failed to read frame data for liveness verification: {}", e.getMessage());
            return errorResponse("Liveness verification frame read error");
        }
    }

    @Override
    public Map<String, Object> verifyPuzzleChallenge(Map<String, Object> request) {
        Object action = request != null ? request.get("action") : null;
        log.debug("Calling biometric service to verify puzzle challenge: action={}", action);
        try {
            return restClient.post()
                    .uri("/liveness/verify-challenge")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(MAP_TYPE);
        } catch (HttpClientErrorException.NotFound e) {
            // Bio route missing — an older biometric-processor image without the
            // /liveness/verify-challenge endpoint. Treat as unavailable (NOT a
            // malformed request) and soft-pass so the training UI keeps working
            // during a rollout where api ships ahead of bio.
            log.warn("Bio /liveness/verify-challenge returned 404 (route not deployed) — soft-passing");
            return puzzleVerdict(true, action, "VALIDATION_UNAVAILABLE", "");
        } catch (HttpClientErrorException e) {
            // Bio rejected the payload as malformed (other 4xx, e.g. pydantic 422).
            // On a TRAINING surface surface this as a clean verified=false verdict
            // rather than a 5xx so the web shows a reason instead of an error toast.
            log.warn("Puzzle challenge rejected by biometric service ({}): {}",
                    e.getStatusCode(), e.getMessage());
            return puzzleVerdict(false, action, "INVALID_REQUEST",
                    "Challenge submission was rejected as malformed.");
        } catch (RestClientException e) {
            // Bio unreachable (ResourceAccessException) or 5xx (HttpServerErrorException)
            // — both subclasses of RestClientException. This is a lightweight training
            // surface, NOT a security gate (the real liveness gate is enrollment/verify),
            // so we soft-pass on infrastructure failure rather than block the user.
            log.error("Biometric service unavailable for puzzle challenge — soft-passing: {}",
                    e.getMessage());
            return puzzleVerdict(true, action, "VALIDATION_UNAVAILABLE", "");
        }
    }

    @Override
    public Map<String, Object> createPuzzleSession(UUID tenantId,
                                                   UUID userId,
                                                   List<String> allowedChallengeTypes,
                                                   int count,
                                                   String difficulty) {
        log.info("Calling biometric service to create puzzle session for user: {} (tenant: {}, count: {})",
                userId, tenantId, count);
        // CV-2 canonical contract: bio POST /api/v1/liveness/puzzle-session
        //   { tenant_id, user_id, allowed_challenge_types:[...], count, difficulty? }
        // The path is relative to the configured base URL, which already carries
        // the /api/v1 prefix at runtime (mirrors verifyPuzzleChallenge → /liveness/...).
        // user_id + tenant_id are SERVER-stamped by the MFA-flow proxy — fail loud
        // rather than POST a null owner the bio side would 422 on / leave unbound.
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("tenant_id", java.util.Objects.requireNonNull(tenantId, "tenantId").toString());
        body.put("user_id", java.util.Objects.requireNonNull(userId, "userId").toString());
        body.put("allowed_challenge_types",
                allowedChallengeTypes != null ? allowedChallengeTypes : java.util.List.of());
        body.put("count", count);
        if (difficulty != null && !difficulty.isBlank()) {
            body.put("difficulty", difficulty);
        }
        try {
            return postJsonObject("/liveness/puzzle-session", body);
        } catch (HttpClientErrorException e) {
            // Bio rejected the request (empty allowed types / bad count → 400/422).
            // Fail-closed: no session_id, so the proxy returns a failure.
            log.warn("Puzzle session create rejected by biometric service: {} {}",
                    e.getStatusCode(), e.getMessage());
            return errorResponse("Puzzle session create rejected: " + e.getResponseBodyAsString());
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for puzzle session create: {}", e.getMessage());
            return errorResponse("Puzzle session service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for puzzle session create: {}", e.getMessage());
            return errorResponse("Puzzle session service error");
        }
    }

    @Override
    public Map<String, Object> submitPuzzleChallenge(String sessionId, Map<String, Object> body) {
        Object action = body != null ? body.get("action") : null;
        log.debug("Calling biometric service to submit puzzle challenge: sessionId={}, action={}",
                sessionId, action);
        // CV-2 canonical contract: bio
        //   POST /api/v1/liveness/puzzle-session/{session_id}/challenge
        //   { action, metrics:{...}, start_timestamp_ms, end_timestamp_ms, confidence }
        // The body is the client's submission forwarded as-is (per-challenge UX,
        // not the auth gate). 404 = unknown/expired/consumed session.
        try {
            return postJsonObject(
                    "/liveness/puzzle-session/" + sessionId + "/challenge",
                    body != null ? body : Map.of());
        } catch (HttpClientErrorException e) {
            // 404 (unknown/expired/consumed) or other 4xx (malformed) — fail-closed:
            // never synthesize a verified verdict for a rejected submission.
            log.warn("Puzzle challenge submit rejected by biometric service: {} {}",
                    e.getStatusCode(), e.getMessage());
            return errorResponse("Puzzle challenge submit rejected: " + e.getResponseBodyAsString());
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for puzzle challenge submit: {}", e.getMessage());
            return errorResponse("Puzzle session service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for puzzle challenge submit: {}", e.getMessage());
            return errorResponse("Puzzle session service error");
        }
    }

    @Override
    public Map<String, Object> getPuzzleVerdict(String sessionId, UUID userId, UUID tenantId) {
        log.info("Calling biometric service for puzzle session verdict: sessionId={}, user: {} (tenant: {})",
                sessionId, userId, tenantId);
        // CV-2 canonical contract (the AUTH GATE): bio
        //   POST /api/v1/liveness/puzzle-session/{session_id}/verdict
        //   { user_id, tenant_id }  → { verified: bool }; CONSUMES the session.
        // user_id + tenant_id are SERVER-stamped (resolved from the MFA session by
        // the PuzzleVerifyMfaStepHandler) — never client-supplied. Fail loud on a
        // null owner rather than POST an unbound verdict request.
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("user_id", java.util.Objects.requireNonNull(userId, "userId").toString());
        body.put("tenant_id", java.util.Objects.requireNonNull(tenantId, "tenantId").toString());
        try {
            return postJsonObject("/liveness/puzzle-session/" + sessionId + "/verdict", body);
        } catch (HttpClientErrorException e) {
            // 404 = unknown/expired session (also single-use already-consumed) —
            // fail-closed: the handler treats the absence of verified:true as a fail.
            log.warn("Puzzle session verdict rejected by biometric service: {} {}",
                    e.getStatusCode(), e.getMessage());
            return errorResponse("Puzzle session verdict rejected: " + e.getResponseBodyAsString());
        } catch (ResourceAccessException e) {
            log.error("Biometric service unreachable for puzzle session verdict: {}", e.getMessage());
            return errorResponse("Puzzle session service unavailable");
        } catch (RestClientException e) {
            log.error("Biometric service error for puzzle session verdict: {}", e.getMessage());
            return errorResponse("Puzzle session service error");
        }
    }

    /** Builds a {@code VerifyChallengeResponse}-shaped verdict map for the puzzle proxy. */
    private Map<String, Object> puzzleVerdict(boolean verified, Object action,
                                              String reasonCode, String message) {
        Map<String, Object> verdict = new java.util.HashMap<>();
        verdict.put("verified", verified);
        verdict.put("action", action);
        verdict.put("duration_seconds", 0.0);
        verdict.put("reason_code", reasonCode);
        verdict.put("message", message);
        return verdict;
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

    /**
     * JSON POST accepting an arbitrary {@code Map<String, Object>} body (the
     * NFC passive-auth request mixes the SOD with a variable set of DG fields).
     */
    private Map<String, Object> postJsonObject(String path, Map<String, Object> body) {
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
