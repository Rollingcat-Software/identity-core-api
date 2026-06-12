package com.fivucsas.identity.application.dto.command;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * JSON request body for the CLIENT-SIDE-EMBEDDING <b>voice</b> enroll endpoint
 * ({@code POST /api/v1/biometric/voice/enroll-embedding/{userId}} — audit H3,
 * GPU-less).
 *
 * <p>Carries the precomputed 256-dim Resemblyzer speaker embedding the browser
 * computed on-device, so the raw audio never leaves the client. This is the
 * embedding counterpart of {@code POST /api/v1/biometric/voice/enroll/{userId}}
 * (which carries base64 audio).</p>
 *
 * <p>The embedding MUST be exactly {@value #EMBEDDING_DIM} elements — the
 * Resemblyzer output dimensionality. A wrong-length (or empty) vector is rejected
 * by bean validation with {@code 400 Bad Request} (the bio side independently
 * re-validates to 256, returning {@code 422}).</p>
 *
 * @param embedding the 256-dim client-side speaker embedding (required, exactly
 *                  {@value #EMBEDDING_DIM} elements)
 * @param tenantId  optional tenant identifier; when null/blank the controller
 *                  derives it from the authenticated principal
 * @param optimize  re-enroll &amp; optimize: when true and the user already has a
 *                  voiceprint, the bio side FUSES this sample into the existing
 *                  centroid (defaults to false via {@link #optimizeOrDefault()})
 */
public record VoiceEnrollEmbeddingRequest(
        @NotEmpty(message = "embedding is required")
        @Size(min = EMBEDDING_DIM, max = EMBEDDING_DIM,
                message = "embedding must contain exactly " + EMBEDDING_DIM + " elements")
        List<Double> embedding,

        @JsonProperty("tenant_id")
        String tenantId,

        Boolean optimize) {

    /**
     * Resemblyzer speaker-embedding output dimensionality. The bio
     * {@code /voice/enroll-embedding} store is a 256-dim pgvector column, so a
     * vector of any other length cannot be a valid template.
     */
    public static final int EMBEDDING_DIM = 256;

    /** Null-safe optimize flag (absent ⇒ false, the plain append/average path). */
    public boolean optimizeOrDefault() {
        return Boolean.TRUE.equals(optimize);
    }
}
