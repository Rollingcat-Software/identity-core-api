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

    private TenantConfiguration(int maxUsers, boolean biometricEnabled,
                                int sessionTimeoutMinutes, int refreshTokenValidityDays,
                                boolean mfaRequired) {
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
    }

    /**
     * Creates a default tenant configuration.
     */
    public static TenantConfiguration defaultConfiguration() {
        return new TenantConfiguration(100, true, 30, 7, false);
    }

    /**
     * Creates a custom tenant configuration.
     */
    public static TenantConfiguration of(int maxUsers, boolean biometricEnabled,
                                         int sessionTimeoutMinutes, int refreshTokenValidityDays,
                                         boolean mfaRequired) {
        return new TenantConfiguration(maxUsers, biometricEnabled,
                                       sessionTimeoutMinutes, refreshTokenValidityDays, mfaRequired);
    }

    /**
     * Creates configuration with updated max users.
     */
    public TenantConfiguration withMaxUsers(int maxUsers) {
        return new TenantConfiguration(maxUsers, this.biometricEnabled,
                                       this.sessionTimeoutMinutes, this.refreshTokenValidityDays,
                                       this.mfaRequired);
    }

    /**
     * Creates configuration with biometric setting changed.
     */
    public TenantConfiguration withBiometricEnabled(boolean enabled) {
        return new TenantConfiguration(this.maxUsers, enabled,
                                       this.sessionTimeoutMinutes, this.refreshTokenValidityDays,
                                       this.mfaRequired);
    }

    /**
     * Creates configuration with MFA requirement changed.
     */
    public TenantConfiguration withMfaRequired(boolean required) {
        return new TenantConfiguration(this.maxUsers, this.biometricEnabled,
                                       this.sessionTimeoutMinutes, this.refreshTokenValidityDays,
                                       required);
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TenantConfiguration that = (TenantConfiguration) o;
        return maxUsers == that.maxUsers &&
               biometricEnabled == that.biometricEnabled &&
               sessionTimeoutMinutes == that.sessionTimeoutMinutes &&
               refreshTokenValidityDays == that.refreshTokenValidityDays &&
               mfaRequired == that.mfaRequired;
    }

    @Override
    public int hashCode() {
        return Objects.hash(maxUsers, biometricEnabled, sessionTimeoutMinutes,
                           refreshTokenValidityDays, mfaRequired);
    }

    @Override
    public String toString() {
        return String.format("TenantConfiguration{maxUsers=%d, biometric=%s, sessionTimeout=%d, " +
                            "refreshValidity=%d, mfaRequired=%s}",
                            maxUsers, biometricEnabled, sessionTimeoutMinutes,
                            refreshTokenValidityDays, mfaRequired);
    }
}
