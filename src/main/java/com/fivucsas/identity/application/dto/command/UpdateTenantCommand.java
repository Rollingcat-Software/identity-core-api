package com.fivucsas.identity.application.dto.command;

import lombok.Builder;
import lombok.Getter;

/**
 * Command for updating an existing tenant.
 */
@Getter
@Builder
public class UpdateTenantCommand {

    private final String tenantId;
    private final String name;
    private final String description;
    private final String contactEmail;
    private final String contactPhone;
    private final Integer maxUsers;
    private final Boolean biometricEnabled;
    private final Integer sessionTimeoutMinutes;
    private final Integer refreshTokenValidityDays;
    private final Boolean mfaRequired;
}
