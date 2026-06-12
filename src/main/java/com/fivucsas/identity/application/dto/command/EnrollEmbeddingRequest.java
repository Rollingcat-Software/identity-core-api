package com.fivucsas.identity.application.dto.command;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * JSON request body for the CLIENT-SIDE-EMBEDDING face enroll endpoint
 * ({@code POST /api/v1/biometric/enroll-embedding/{userId}} — sub-project A,
 * Phase 6).
 *
 * <p>Carries the precomputed 512-dim Facenet512 embedding the browser computed
 * on-device, so the raw face image never leaves the client. This is the JSON
 * counterpart of the multipart {@code POST /api/v1/biometric/enroll/{userId}}:
 * the multipart controller can only carry a {@code MultipartFile}, never a
 * {@code List<Double>}, so before this DTO existed the
 * {@code EnrollBiometricCommand.embedding} branch in {@code EnrollBiometricService}
 * was unreachable (the Phase-6 TODO).</p>
 *
 * <p>The embedding MUST be exactly {@value #EMBEDDING_DIM} elements — the
 * Facenet512 output dimensionality. A wrong-length (or empty) vector is rejected
 * by bean validation with {@code 400 Bad Request} (a malformed client payload),
 * matching the {@code GlobalExceptionHandler} mapping for
 * {@code MethodArgumentNotValidException}.</p>
 *
 * @param embedding the 512-dim client-side Facenet512 embedding (required,
 *                  exactly {@value #EMBEDDING_DIM} elements)
 * @param tenantId  optional tenant identifier (pgvector tenant scoping on the bio
 *                  side). When null/blank the controller derives it from the
 *                  authenticated principal, mirroring the face-search path; an
 *                  explicit value mirrors the multipart enroll's {@code tenant_id}
 *                  request param.
 */
public record EnrollEmbeddingRequest(
        @NotEmpty(message = "embedding is required")
        @Size(min = EMBEDDING_DIM, max = EMBEDDING_DIM,
                message = "embedding must contain exactly " + EMBEDDING_DIM + " elements")
        List<Double> embedding,

        @JsonProperty("tenant_id")
        String tenantId) {

    /**
     * Facenet512 output dimensionality. The bio {@code /enroll-embedding} store
     * is a 512-dim pgvector column, so a vector of any other length cannot be a
     * valid template.
     */
    public static final int EMBEDDING_DIM = 512;
}
