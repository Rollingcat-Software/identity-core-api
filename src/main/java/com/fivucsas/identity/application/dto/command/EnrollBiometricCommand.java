package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

/**
 * Command for enrolling biometric data.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains biometric enrollment data
 * - Command Pattern: Represents biometric enrollment action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EnrollBiometricCommand {

    private String userId;
    private MultipartFile faceImage;

    /**
     * Optional tenant identifier — required by the biometric processor for
     * pgvector tenant scoping. When null, bio falls back to non-scoped
     * matching (legacy behavior).
     */
    private String tenantId;

    /**
     * Optional single client-side pre-filter embedding (JSON-encoded array,
     * 512-dim landmark-geometry vector). D2 architectural decision: log-only,
     * never used for auth.
     */
    private String clientEmbedding;

    /**
     * Optional array-of-arrays of client-side embeddings (JSON string), used
     * when more than one client view is captured. Either embedding field may
     * be null/empty.
     */
    private String clientEmbeddings;

    /**
     * "Re-enroll &amp; optimize": when true (and the user already has a stored
     * template), the biometric-processor FUSES this capture into the existing
     * centroid instead of a plain append/replace. Forwarded to the bio
     * {@code /enroll} endpoint. Default false (normal enroll).
     */
    private boolean optimize;
}
