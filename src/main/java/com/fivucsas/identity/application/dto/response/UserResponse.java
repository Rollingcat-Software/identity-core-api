package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;

/**
 * Response for user data.
 *
 * Following principles:
 * - Single Responsibility: Only contains user response data
 * - Data Transfer: No business logic
 * - Security: Excludes sensitive data (password hash)
 */
@Data
@Builder(toBuilder = true)
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
    private boolean emailVerified;
    private boolean phoneVerified;
    private String role;
    private Set<String> roles;
    /**
     * Platform-level tier (the {@link com.fivucsas.identity.entity.UserType} enum
     * NAME — "ROOT" / "TENANT_ADMIN" / "TENANT_MEMBER" / "GUEST"). This is the SOLE
     * authority for the platform tier (every backend gate keys off it); the
     * frontend trusts this rather than inferring the tier from {@link #role}.
     * See docs/IDENTITY_ROLE_UNIFICATION.md.
     */
    private String userType;
    private String tenantId;
    private String tenantName;
    private boolean isBiometricEnrolled;
    private Instant enrolledAt;
    private Instant lastVerifiedAt;
    private int verificationCount;
    private Instant lastLoginAt;
    private String lastLoginIp;
    private Instant createdAt;
    private Instant updatedAt;
}
