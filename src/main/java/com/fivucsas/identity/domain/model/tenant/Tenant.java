package com.fivucsas.identity.domain.model.tenant;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Pure domain model for Tenant.
 * Represents an organization/company using the identity service.
 *
 * No JPA annotations - this is a pure domain concept.
 * Business logic lives here; persistence is handled by infrastructure.
 */
public class Tenant {

    private final UUID id;
    private String name;
    private final String slug;
    private String description;
    private String contactEmail;
    private String contactPhone;
    private TenantStatus status;
    private TenantConfiguration configuration;
    private final Instant createdAt;
    private Instant updatedAt;

    private Tenant(UUID id, String name, String slug, String description,
                   String contactEmail, String contactPhone, TenantStatus status,
                   TenantConfiguration configuration, Instant createdAt, Instant updatedAt) {
        this.id = id;
        this.name = Objects.requireNonNull(name, "Tenant name cannot be null");
        this.slug = Objects.requireNonNull(slug, "Tenant slug cannot be null");
        this.description = description;
        this.contactEmail = Objects.requireNonNull(contactEmail, "Contact email cannot be null");
        this.contactPhone = contactPhone;
        this.status = status != null ? status : TenantStatus.PENDING;
        this.configuration = configuration != null ? configuration : TenantConfiguration.defaultConfiguration();
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    // ========== Factory Methods ==========

    /**
     * Creates a new tenant in PENDING status.
     */
    public static Tenant create(String name, String slug, String description,
                                String contactEmail, String contactPhone) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Tenant name cannot be null or empty");
        }
        if (slug == null || slug.trim().isEmpty()) {
            throw new IllegalArgumentException("Tenant slug cannot be null or empty");
        }
        if (contactEmail == null || contactEmail.trim().isEmpty()) {
            throw new IllegalArgumentException("Contact email cannot be null or empty");
        }
        Instant now = Instant.now();
        return new Tenant(null, name, slug, description, contactEmail, contactPhone,
                         TenantStatus.PENDING, TenantConfiguration.defaultConfiguration(), now, now);
    }

    /**
     * Reconstitutes a tenant from persistence.
     */
    public static Tenant reconstitute(UUID id, String name, String slug, String description,
                                      String contactEmail, String contactPhone,
                                      TenantStatus status, TenantConfiguration configuration,
                                      Instant createdAt, Instant updatedAt) {
        return new Tenant(id, name, slug, description, contactEmail, contactPhone,
                         status, configuration, createdAt, updatedAt);
    }

    // ========== Business Methods ==========

    public void activate() {
        this.status = TenantStatus.ACTIVE;
        this.updatedAt = Instant.now();
    }

    public void deactivate() {
        this.status = TenantStatus.INACTIVE;
        this.updatedAt = Instant.now();
    }

    public void suspend() {
        this.status = TenantStatus.SUSPENDED;
        this.updatedAt = Instant.now();
    }

    public void startTrial() {
        this.status = TenantStatus.TRIAL;
        this.updatedAt = Instant.now();
    }

    public void updateContactInfo(String contactEmail, String contactPhone) {
        if (contactEmail == null || contactEmail.trim().isEmpty()) {
            throw new IllegalArgumentException("Contact email cannot be null or empty");
        }
        this.contactEmail = contactEmail;
        this.contactPhone = contactPhone;
        this.updatedAt = Instant.now();
    }

    public void updateConfiguration(TenantConfiguration configuration) {
        if (configuration == null) {
            throw new IllegalArgumentException("Configuration cannot be null");
        }
        this.configuration = configuration;
        this.updatedAt = Instant.now();
    }

    public void updateDetails(String name, String description) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Tenant name cannot be null or empty");
        }
        this.name = name;
        this.description = description;
        this.updatedAt = Instant.now();
    }

    public boolean isActive() {
        return this.status == TenantStatus.ACTIVE;
    }

    public boolean isSuspended() {
        return this.status == TenantStatus.SUSPENDED;
    }

    public boolean isInTrial() {
        return this.status == TenantStatus.TRIAL;
    }

    public boolean canAcceptUsers() {
        return isActive() || isInTrial();
    }

    public boolean hasBiometricFeatures() {
        return configuration.isBiometricEnabled() && canAcceptUsers();
    }

    /**
     * Returns tenant ID as value object.
     */
    public TenantId getTenantId() {
        return id != null ? TenantId.of(id) : null;
    }

    // ========== Getters ==========

    public UUID getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getSlug() {
        return slug;
    }

    public String getDescription() {
        return description;
    }

    public String getContactEmail() {
        return contactEmail;
    }

    public String getContactPhone() {
        return contactPhone;
    }

    public TenantStatus getStatus() {
        return status;
    }

    public TenantConfiguration getConfiguration() {
        return configuration;
    }

    public int getMaxUsers() {
        return configuration.getMaxUsers();
    }

    public boolean isBiometricEnabled() {
        return configuration.isBiometricEnabled();
    }

    public int getSessionTimeoutMinutes() {
        return configuration.getSessionTimeoutMinutes();
    }

    public int getRefreshTokenValidityDays() {
        return configuration.getRefreshTokenValidityDays();
    }

    public boolean isMfaRequired() {
        return configuration.isMfaRequired();
    }

    public boolean isEnforceDomainMatching() {
        return configuration.isEnforceDomainMatching();
    }

    /** Per-tenant default member role (V64); {@code null} = seeded baseline. */
    public String getDefaultMemberRole() {
        return configuration.getDefaultMemberRole();
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Tenant tenant)) return false;
        return id != null && id.equals(tenant.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @Override
    public String toString() {
        return "Tenant{id=" + id + ", name='" + name + "', slug='" + slug +
               "', status=" + status + "}";
    }
}
