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
    private final Boolean enforceDomainMatching;
    /**
     * Name of the per-tenant role auto-assigned to users who join via a verified
     * email domain (V64). {@code null} = leave unchanged; blank = clear (fall
     * back to the seeded baseline role).
     */
    private final String defaultMemberRole;
}
