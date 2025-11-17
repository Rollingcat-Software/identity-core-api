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
}
