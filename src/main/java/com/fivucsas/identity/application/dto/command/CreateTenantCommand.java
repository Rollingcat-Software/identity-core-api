package com.fivucsas.identity.application.dto.command;

import lombok.Builder;
import lombok.Getter;

/**
 * Command for creating a new tenant.
 */
@Getter
@Builder
public class CreateTenantCommand {

    private final String name;
    private final String slug;
    private final String description;
    private final String contactEmail;
    private final String contactPhone;
    private final Integer maxUsers;
    private final Boolean biometricEnabled;
    private final Integer sessionTimeoutMinutes;
    private final Integer refreshTokenValidityDays;
    private final Boolean mfaRequired;
}
