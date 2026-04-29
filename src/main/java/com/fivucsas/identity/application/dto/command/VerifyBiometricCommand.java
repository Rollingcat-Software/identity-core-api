package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

/**
 * Command for verifying biometric data.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains biometric verification data
 * - Command Pattern: Represents biometric verification action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyBiometricCommand {

    private String userId;
    private MultipartFile faceImage;

    /**
     * Optional tenant identifier — required by the biometric processor for
     * pgvector tenant-scoped match queries. When null, bio falls back to
     * non-scoped matching.
     */
    private String tenantId;

    /**
     * Optional single client-side pre-filter embedding (D2 log-only).
     */
    private String clientEmbedding;

    /**
     * Optional array-of-arrays of client-side embeddings (D2 log-only).
     */
    private String clientEmbeddings;
}
