package com.fivucsas.identity.application.dto.response;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.List;

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
    private final int currentUsers;
    private final boolean biometricEnabled;
    private final int sessionTimeoutMinutes;
    private final int refreshTokenValidityDays;
    private final boolean mfaRequired;
    private final boolean enforceDomainMatching;
    /**
     * Name of the per-tenant role auto-assigned to users who join via a
     * verified email domain (V64). {@code null} = the seeded baseline role.
     */
    private final String defaultMemberRole;
    /**
     * The tenant's email-domain registry (V44). Populated so the admin UI can
     * render current state without a second round-trip. May be {@code null}
     * for list/summary responses that do not eagerly load domains.
     */
    private final List<TenantEmailDomainResponse> emailDomains;
    private final Instant createdAt;
    private final Instant updatedAt;
}
