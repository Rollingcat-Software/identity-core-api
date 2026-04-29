package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.tenant.TenantConfiguration;
import com.fivucsas.identity.domain.model.tenant.TenantId;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Tenant aggregate root entity.
 * Represents an organization/company using the identity service.
 *
 * <p><b>Soft-delete contract (EDGE-P1 #5, V49):</b>
 * {@code tenants.id} is referenced by ~13 child tables, most with
 * {@code ON DELETE CASCADE}. A hard delete would silently wipe ~10
 * dependent tables. This entity therefore intercepts {@code delete*} via
 * {@link SQLDelete} (rewrites to {@code UPDATE tenants SET deleted_at = NOW()})
 * and filters reads via {@link SQLRestriction} (skips tombstoned rows).
 * Hard delete is FORBIDDEN at the application layer; use
 * {@code ManageTenantService.softDeleteTenant(UUID)}.
 *
 * Following principles:
 * - Rich Domain Model: Business logic in entity
 * - Encapsulation: No public setters for critical fields
 * - Single Responsibility: Tenant manages its own state
 */
@Entity
@Table(name = "tenants")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // For JPA
@AllArgsConstructor(access = AccessLevel.PRIVATE) // For Builder
@Builder
@SQLDelete(sql = "UPDATE tenants SET deleted_at = NOW() WHERE id = ?")
@SQLRestriction("deleted_at IS NULL")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false, length = 100)
    private String name;

    @Column(unique = true, nullable = false, length = 50)
    private String slug;

    @Column(length = 500)
    private String description;

    @Column(name = "contact_email", nullable = false, length = 255)
    private String contactEmail;

    @Column(name = "contact_phone", length = 20)
    private String contactPhone;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private TenantStatus status = TenantStatus.PENDING;

    // Configuration stored as JSON or separate columns
    @Column(name = "max_users")
    @Builder.Default
    private int maxUsers = 100;

    @Column(name = "biometric_enabled")
    @Builder.Default
    private boolean biometricEnabled = true;

    @Column(name = "session_timeout_minutes")
    @Builder.Default
    private int sessionTimeoutMinutes = 30;

    @Column(name = "refresh_token_validity_days")
    @Builder.Default
    private int refreshTokenValidityDays = 7;

    @Column(name = "mfa_required")
    @Builder.Default
    private boolean mfaRequired = false;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    /**
     * Soft-delete tombstone. NULL = active row, NON-NULL = soft-deleted.
     *
     * <p>Set automatically by Hibernate via the {@code @SQLDelete} statement
     * on this entity (UPDATE tenants SET deleted_at = NOW() ... ). All JPA
     * finds are filtered by {@code @SQLRestriction("deleted_at IS NULL")}
     * so soft-deleted rows are invisible to default queries.
     *
     * <p>Schema documented by Flyway V49.
     */
    @Column(name = "deleted_at")
    private Instant deletedAt;

    // ========== Auth Flow Relationships ==========

    @OneToMany(mappedBy = "tenant", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @Builder.Default
    private List<TenantAuthMethod> authMethods = new ArrayList<>();

    @OneToMany(mappedBy = "tenant", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @Builder.Default
    private List<AuthFlow> authFlows = new ArrayList<>();

    // ========== Value Object Getters ==========

    /**
     * Returns tenant ID as value object.
     */
    public TenantId getTenantId() {
        return id != null ? TenantId.of(id) : null;
    }

    /**
     * Returns tenant configuration as value object.
     */
    public TenantConfiguration getConfiguration() {
        return TenantConfiguration.of(
            maxUsers,
            biometricEnabled,
            sessionTimeoutMinutes,
            refreshTokenValidityDays,
            mfaRequired
        );
    }

    // ========== Business Methods ==========

    /**
     * Activates the tenant.
     */
    public void activate() {
        this.status = TenantStatus.ACTIVE;
    }

    /**
     * Deactivates the tenant.
     */
    public void deactivate() {
        this.status = TenantStatus.INACTIVE;
    }

    /**
     * Suspends the tenant.
     */
    public void suspend() {
        this.status = TenantStatus.SUSPENDED;
    }

    /**
     * Starts trial period for tenant.
     */
    public void startTrial() {
        this.status = TenantStatus.TRIAL;
    }

    /**
     * Updates tenant contact information.
     */
    public void updateContactInfo(String contactEmail, String contactPhone) {
        if (contactEmail == null || contactEmail.trim().isEmpty()) {
            throw new IllegalArgumentException("Contact email cannot be null or empty");
        }
        this.contactEmail = contactEmail;
        this.contactPhone = contactPhone;
    }

    /**
     * Updates tenant configuration.
     */
    public void updateConfiguration(TenantConfiguration configuration) {
        if (configuration == null) {
            throw new IllegalArgumentException("Configuration cannot be null");
        }
        this.maxUsers = configuration.getMaxUsers();
        this.biometricEnabled = configuration.isBiometricEnabled();
        this.sessionTimeoutMinutes = configuration.getSessionTimeoutMinutes();
        this.refreshTokenValidityDays = configuration.getRefreshTokenValidityDays();
        this.mfaRequired = configuration.isMfaRequired();
    }

    /**
     * Updates tenant name and description.
     */
    public void updateDetails(String name, String description) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Tenant name cannot be null or empty");
        }
        this.name = name;
        this.description = description;
    }

    /**
     * Checks if tenant is active.
     */
    public boolean isActive() {
        return this.status == TenantStatus.ACTIVE;
    }

    /**
     * Checks if tenant is suspended.
     */
    public boolean isSuspended() {
        return this.status == TenantStatus.SUSPENDED;
    }

    /**
     * Checks if tenant is in trial.
     */
    public boolean isInTrial() {
        return this.status == TenantStatus.TRIAL;
    }

    /**
     * Checks if tenant can accept new users.
     */
    public boolean canAcceptUsers() {
        return isActive() || isInTrial();
    }

    /**
     * Checks if biometric features are available for this tenant.
     */
    public boolean hasBiometricFeatures() {
        return biometricEnabled && canAcceptUsers();
    }

    /**
     * Returns true if this tenant has been soft-deleted
     * (i.e. {@code deleted_at} is set).
     *
     * <p>Default JPA queries filter these rows out via
     * {@code @SQLRestriction}, so callers will only see
     * {@code isDeleted() == true} on rows fetched via native queries
     * or admin restore screens.
     */
    public boolean isDeleted() {
        return deletedAt != null;
    }
}
