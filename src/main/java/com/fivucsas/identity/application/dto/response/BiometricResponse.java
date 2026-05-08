package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response for biometric operations (enroll, verify).
 *
 * Following principles:
 * - Single Responsibility: Only contains biometric response data
 * - Data Transfer: No business logic
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BiometricResponse {

    private boolean success;
    private String message;
    private Double confidence;  // Confidence score for verification
    private String userId;

    /**
     * Raw cosine distance between the query and the matched enrolled
     * template (lower is better). Forwarded from the biometric processor's
     * /verify response. Null when the upstream did not include it (older
     * builds or non-match-bearing responses). See
     * INVESTIGATION_MASTER_2026-05-07 §wires "Face-verify response missing
     * distance/threshold".
     */
    private Double distance;

    /**
     * Decision threshold the biometric processor compared the distance
     * against. Echoes the real value used for THIS verification so the UI
     * can render the margin instead of inventing sentinels.
     */
    private Double threshold;
}
