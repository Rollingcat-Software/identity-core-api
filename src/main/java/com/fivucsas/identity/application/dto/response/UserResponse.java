package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Response for user data.
 *
 * Following principles:
 * - Single Responsibility: Only contains user response data
 * - Data Transfer: No business logic
 * - Security: Excludes sensitive data (password hash)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {

    private String id;
    private String email;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String address;
    private String idNumber;  // Will be masked
    private String status;
    private boolean isBiometricEnrolled;
    private Instant enrolledAt;
    private Instant lastVerifiedAt;
    private int verificationCount;
    private Instant createdAt;
    private Instant updatedAt;
}
