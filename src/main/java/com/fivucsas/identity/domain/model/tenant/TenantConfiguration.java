package com.fivucsas.identity.domain.model.tenant;

import java.util.Objects;

/**
 * Value Object representing a Tenant's configuration settings.
 * Immutable and validated.
 *
 * Following principles:
 * - Immutability: Thread-safe configuration
 * - Encapsulation: Validates configuration values
 * - Single Responsibility: Only handles tenant settings
 */
public final class TenantConfiguration {

    private final int maxUsers;
    private final boolean biometricEnabled;
    private final int sessionTimeoutMinutes;
    private final int refreshTokenValidityDays;
    private final boolean mfaRequired;
    private final boolean enforceDomainMatching;
    /**
     * Name of the per-tenant role auto-assigned to users who join via a verified
     * email domain (V64). {@code null} = fall back to the seeded baseline role.
     */
    private final String defaultMemberRole;

    private TenantConfiguration(int maxUsers, boolean biometricEnabled,
                                int sessionTimeoutMinutes, int refreshTokenValidityDays,
                                boolean mfaRequired, boolean enforceDomainMatching,
                                String defaultMemberRole) {
        if (maxUsers < 1) {
            throw new IllegalArgumentException("Max users must be at least 1");
        }
        if (sessionTimeoutMinutes < 1) {
            throw new IllegalArgumentException("Session timeout must be at least 1 minute");
        }
        if (refreshTokenValidityDays < 1) {
            throw new IllegalArgumentException("Refresh token validity must be at least 1 day");
        }

        this.maxUsers = maxUsers;
        this.biometricEnabled = biometricEnabled;
        this.sessionTimeoutMinutes = sessionTimeoutMinutes;
        this.refreshTokenValidityDays = refreshTokenValidityDays;
        this.mfaRequired = mfaRequired;
        this.enforceDomainMatching = enforceDomainMatching;
        this.defaultMemberRole = (defaultMemberRole == null || defaultMemberRole.isBlank())
                ? null : defaultMemberRole.trim();
    }

    /**
     * Creates a default tenant configuration.
     */
    public static TenantConfiguration defaultConfiguration() {
        return new TenantConfiguration(100, true, 30, 7, false, false, null);
    }

    /**
     * Creates a custom tenant configuration.
     *
     * <p>Backwards-compatible overload that defaults
     * {@code enforceDomainMatching} to {@code false} (the V62 default). Prefer
     * the 6-arg overload when the flag is known.</p>
     */
    public static TenantConfiguration of(int maxUsers, boolean biometricEnabled,
                                         int sessionTimeoutMinutes, int refreshTokenValidityDays,
                                         boolean mfaRequired) {
        return new TenantConfiguration(maxUsers, biometricEnabled,
                                       sessionTimeoutMinutes, refreshTokenValidityDays, mfaRequired,
                                       false, null);
    }

    /**
     * Creates a custom tenant configuration including the V62 opt-in
     * email-domain enforcement flag.
     */
    public static TenantConfiguration of(int maxUsers, boolean biometricEnabled,
                                         int sessionTimeoutMinutes, int refreshTokenValidityDays,
                                         boolean mfaRequired, boolean enforceDomainMatching) {
        return new TenantConfiguration(maxUsers, biometricEnabled,
                                       sessionTimeoutMinutes, refreshTokenValidityDays, mfaRequired,
                                       enforceDomainMatching, null);
    }

    /**
     * Creates a custom tenant configuration including the V64 per-tenant default
     * member role.
     */
    public static TenantConfiguration of(int maxUsers, boolean biometricEnabled,
                                         int sessionTimeoutMinutes, int refreshTokenValidityDays,
                                         boolean mfaRequired, boolean enforceDomainMatching,
                                         String defaultMemberRole) {
        return new TenantConfiguration(maxUsers, biometricEnabled,
                                       sessionTimeoutMinutes, refreshTokenValidityDays, mfaRequired,
                                       enforceDomainMatching, defaultMemberRole);
    }

    /**
     * Creates configuration with updated max users.
     */
    public TenantConfiguration withMaxUsers(int maxUsers) {
        return new TenantConfiguration(maxUsers, this.biometricEnabled,
                                       this.sessionTimeoutMinutes, this.refreshTokenValidityDays,
                                       this.mfaRequired, this.enforceDomainMatching, this.defaultMemberRole);
    }

    /**
     * Creates configuration with biometric setting changed.
     */
    public TenantConfiguration withBiometricEnabled(boolean enabled) {
        return new TenantConfiguration(this.maxUsers, enabled,
                                       this.sessionTimeoutMinutes, this.refreshTokenValidityDays,
                                       this.mfaRequired, this.enforceDomainMatching, this.defaultMemberRole);
    }

    /**
     * Creates configuration with MFA requirement changed.
     */
    public TenantConfiguration withMfaRequired(boolean required) {
        return new TenantConfiguration(this.maxUsers, this.biometricEnabled,
                                       this.sessionTimeoutMinutes, this.refreshTokenValidityDays,
                                       required, this.enforceDomainMatching, this.defaultMemberRole);
    }

    /**
     * Creates configuration with the email-domain enforcement flag changed.
     */
    public TenantConfiguration withEnforceDomainMatching(boolean enforce) {
        return new TenantConfiguration(this.maxUsers, this.biometricEnabled,
                                       this.sessionTimeoutMinutes, this.refreshTokenValidityDays,
                                       this.mfaRequired, enforce, this.defaultMemberRole);
    }

    /**
     * Creates configuration with the V64 default member role changed.
     */
    public TenantConfiguration withDefaultMemberRole(String defaultMemberRole) {
        return new TenantConfiguration(this.maxUsers, this.biometricEnabled,
                                       this.sessionTimeoutMinutes, this.refreshTokenValidityDays,
                                       this.mfaRequired, this.enforceDomainMatching, defaultMemberRole);
    }

    public int getMaxUsers() {
        return maxUsers;
    }

    public boolean isBiometricEnabled() {
        return biometricEnabled;
    }

    public int getSessionTimeoutMinutes() {
        return sessionTimeoutMinutes;
    }

    public int getRefreshTokenValidityDays() {
        return refreshTokenValidityDays;
    }

    public boolean isMfaRequired() {
        return mfaRequired;
    }

    public boolean isEnforceDomainMatching() {
        return enforceDomainMatching;
    }

    /** Per-tenant default member role (V64); {@code null} = seeded baseline. */
    public String getDefaultMemberRole() {
        return defaultMemberRole;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TenantConfiguration that = (TenantConfiguration) o;
        return maxUsers == that.maxUsers &&
               biometricEnabled == that.biometricEnabled &&
               sessionTimeoutMinutes == that.sessionTimeoutMinutes &&
               refreshTokenValidityDays == that.refreshTokenValidityDays &&
               mfaRequired == that.mfaRequired &&
               enforceDomainMatching == that.enforceDomainMatching &&
               Objects.equals(defaultMemberRole, that.defaultMemberRole);
    }

    @Override
    public int hashCode() {
        return Objects.hash(maxUsers, biometricEnabled, sessionTimeoutMinutes,
                           refreshTokenValidityDays, mfaRequired, enforceDomainMatching,
                           defaultMemberRole);
    }

    @Override
    public String toString() {
        return String.format("TenantConfiguration{maxUsers=%d, biometric=%s, sessionTimeout=%d, " +
                            "refreshValidity=%d, mfaRequired=%s, enforceDomainMatching=%s, " +
                            "defaultMemberRole=%s}",
                            maxUsers, biometricEnabled, sessionTimeoutMinutes,
                            refreshTokenValidityDays, mfaRequired, enforceDomainMatching,
                            defaultMemberRole);
    }
}
