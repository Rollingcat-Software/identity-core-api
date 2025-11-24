package com.fivucsas.identity.application.dto.response;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Response DTO for tenant information.
 */
@Getter
@Builder
public class TenantResponse {

    private final String id;
    private final String name;
    private final String slug;
    private final String description;
    private final String contactEmail;
    private final String contactPhone;
    private final String status;
    private final int maxUsers;
    private final boolean biometricEnabled;
    private final int sessionTimeoutMinutes;
    private final int refreshTokenValidityDays;
    private final boolean mfaRequired;
    private final Instant createdAt;
    private final Instant updatedAt;
}
