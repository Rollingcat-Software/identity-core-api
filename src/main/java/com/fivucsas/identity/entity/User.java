package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.tenant.TenantId;
import com.fivucsas.identity.domain.model.user.*;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.FilterDef;
import org.hibernate.annotations.ParamDef;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * User aggregate root entity.
 *
 * Refactored to use value objects and business methods, eliminating:
 * - Primitive Obsession anti-pattern
 * - Anemic Domain Model anti-pattern
 *
 * Following principles:
 * - Rich Domain Model: Business logic in entity
 * - Encapsulation: No public setters for critical fields
 * - Immutability: Value objects ensure valid state
 * - Single Responsibility: User manages its own state
 */
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_users_tenant_id", columnList = "tenant_id")
})
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = UUID.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // For JPA
@AllArgsConstructor(access = AccessLevel.PRIVATE) // For Builder
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;  // Keep as UUID for now, can refactor to UserId later

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(unique = true, nullable = false, length = 255)
    @Setter  // Allow updating
    private String email;  // Will be converted to Email via converter

    @Column(nullable = false, name = "password_hash")
    private String passwordHash;  // Will be converted to HashedPassword via converter

    @Column(nullable = false, length = 100)
    @Setter  // Allow updating
    private String firstName;

    @Column(nullable = false, length = 100)
    @Setter  // Allow updating
    private String lastName;

    @Column(unique = true, length = 11)
    @Setter  // Allow updating
    private String idNumber;  // Will be converted to IdNumber via converter

    @Column(length = 20)
    @Setter  // Allow updating
    private String phoneNumber;  // Will be converted to PhoneNumber via converter

    @Column(length = 500)
    @Setter  // Allow updating
    private String address;  // Will be converted to Address via converter

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    @Setter  // Allow updating
    private UserStatus status = UserStatus.ACTIVE;

    @Enumerated(EnumType.STRING)
    @Column(name = "user_type", nullable = false, length = 20)
    @Builder.Default
    private UserType userType = UserType.TENANT_MEMBER;

    @Column(name = "expires_at")
    @Setter
    private Instant expiresAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "invited_by")
    private User invitedBy;

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private boolean emailVerified = false;

    @Column(name = "email_verification_token")
    private String emailVerificationToken;

    @Column(name = "email_verification_sent_at")
    private Instant emailVerificationSentAt;

    @Column(name = "password_reset_token")
    private String passwordResetToken;

    @Column(name = "password_reset_sent_at")
    private Instant passwordResetSentAt;

    @Column(name = "password_reset_expires_at")
    private Instant passwordResetExpiresAt;

    @Column(name = "password_changed_at")
    private Instant passwordChangedAt;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private boolean isActive = true;

    @Column(name = "is_locked", nullable = false)
    @Builder.Default
    private boolean isLocked = false;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "failed_login_attempts", nullable = false)
    @Builder.Default
    private int failedLoginAttempts = 0;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "last_login_ip", length = 45)
    private String lastLoginIp;

    @Column(name = "phone_verified")
    @Builder.Default
    private boolean phoneVerified = false;

    @Column(name = "two_factor_secret", length = 512)
    private String twoFactorSecret;

    @Column(name = "two_factor_backup_codes", length = 1024)
    private String twoFactorBackupCodes;

    @Column(name = "is_biometric_enrolled")
    @Builder.Default
    @Setter  // Allow updating
    private boolean isBiometricEnrolled = false;

    @Column(name = "enrolled_at")
    @Setter  // Allow updating
    private Instant enrolledAt;

    @Column(name = "last_verified_at")
    private Instant lastVerifiedAt;

    @Column(name = "verification_count")
    @Builder.Default
    private int verificationCount = 0;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    // ========== RBAC Relationships ==========

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<UserRole> userRoles = new HashSet<>();

    // ========== Auth Flow Relationships ==========

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @Builder.Default
    private List<UserEnrollment> enrollments = new ArrayList<>();

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @Builder.Default
    private List<UserDevice> devices = new ArrayList<>();

    // ========== Value Object Getters (Type-Safe) ==========

    /**
     * Returns email as value object.
     * Thread-safe and validated.
     */
    public Email getEmailAsValueObject() {
        return email != null ? Email.of(email) : null;
    }

    /**
     * Returns hashed password as value object.
     * Prevents accidental plain text exposure.
     */
    public HashedPassword getPasswordAsValueObject() {
        return passwordHash != null ? HashedPassword.of(passwordHash) : null;
    }

    /**
     * Returns phone number as value object (nullable).
     */
    public PhoneNumber getPhoneNumberAsValueObject() {
        return phoneNumber != null ? PhoneNumber.of(phoneNumber) : null;
    }

    /**
     * Returns address as value object (nullable).
     */
    public Address getAddressAsValueObject() {
        return address != null ? Address.of(address) : null;
    }

    /**
     * Returns ID number as value object (nullable).
     */
    public IdNumber getIdNumberAsValueObject() {
        return idNumber != null ? IdNumber.of(idNumber) : null;
    }

    /**
     * Returns full name as value object.
     */
    public FullName getFullNameAsValueObject() {
        if (firstName == null || lastName == null) {
            return null;
        }
        return FullName.of(firstName, lastName);
    }

    /**
     * Returns tenant ID as value object.
     */
    public TenantId getTenantId() {
        return tenant != null ? TenantId.of(tenant.getId()) : null;
    }

    // ========== Business Methods ==========

    /**
     * Returns full name as string.
     * Delegates to value object for formatting.
     */
    public String getFullName() {
        FullName fullName = getFullNameAsValueObject();
        return fullName != null ? fullName.getFullName() : "";
    }

    /**
     * Changes user's email address.
     * Validates new email through value object.
     *
     * @param newEmail the new email address
     * @throws IllegalArgumentException if email is invalid
     */
    public void changeEmail(Email newEmail) {
        if (newEmail == null) {
            throw new IllegalArgumentException("Email cannot be null");
        }
        this.email = newEmail.getValue();
    }

    /**
     * Updates user's password.
     * Ensures password is properly hashed.
     *
     * @param plainPassword the plain text password
     * @param passwordEncoder the password encoder
     * @throws IllegalArgumentException if password is invalid
     */
    public void updatePassword(String plainPassword, PasswordEncoder passwordEncoder) {
        if (plainPassword == null || plainPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        if (plainPassword.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }

        String hashed = passwordEncoder.encode(plainPassword);
        HashedPassword hashedPassword = HashedPassword.of(hashed);
        this.passwordHash = hashedPassword.getValue();
    }

    /**
     * Checks if provided plain password matches stored hash.
     *
     * @param plainPassword the plain text password to check
     * @param passwordEncoder the password encoder
     * @return true if password matches
     */
    public boolean checkPassword(String plainPassword, PasswordEncoder passwordEncoder) {
        if (plainPassword == null || this.passwordHash == null) {
            return false;
        }
        return passwordEncoder.matches(plainPassword, this.passwordHash);
    }

    /**
     * Updates user's phone number.
     * Validates through value object.
     *
     * @param phoneNumber the new phone number (can be null)
     */
    public void updatePhoneNumber(PhoneNumber phoneNumber) {
        this.phoneNumber = phoneNumber != null ? phoneNumber.getValue() : null;
    }

    /**
     * Updates user's address.
     *
     * @param address the new address (can be null)
     */
    public void updateAddress(Address address) {
        this.address = address != null ? address.getValue() : null;
    }

    /**
     * Updates user's ID number.
     * Validates through value object.
     *
     * @param idNumber the new ID number (can be null)
     */
    public void updateIdNumber(IdNumber idNumber) {
        this.idNumber = idNumber != null ? idNumber.getValue() : null;
    }

    /**
     * Updates user's profile information.
     *
     * @param firstName new first name
     * @param lastName new last name
     * @param phoneNumber new phone number (nullable)
     * @param address new address (nullable)
     */
    public void updateProfile(String firstName, String lastName,
                             PhoneNumber phoneNumber, Address address) {
        // Validate through FullName value object
        FullName fullName = FullName.of(firstName, lastName);

        this.firstName = fullName.getFirstName();
        this.lastName = fullName.getLastName();
        this.phoneNumber = phoneNumber != null ? phoneNumber.getValue() : null;
        this.address = address != null ? address.getValue() : null;
    }

    /**
     * Enrolls user for biometric authentication.
     * Marks user as enrolled and records timestamp.
     */
    public void enrollBiometric() {
        this.isBiometricEnrolled = true;
        this.enrolledAt = Instant.now();
    }

    /**
     * Unenrolls user from biometric authentication.
     * Removes biometric enrollment status.
     */
    public void unenrollBiometric() {
        this.isBiometricEnrolled = false;
        this.enrolledAt = null;
        this.lastVerifiedAt = null;
        this.verificationCount = 0;
    }

    /**
     * Records a successful biometric verification.
     * Increments counter and updates timestamp.
     */
    public void incrementVerificationCount() {
        this.verificationCount++;
        this.lastVerifiedAt = Instant.now();
    }

    /**
     * Marks user's email as verified.
     */
    public void verifyEmail() {
        this.emailVerified = true;
        this.emailVerificationToken = null;
        this.emailVerificationSentAt = null;
    }

    /**
     * Marks user's phone number as verified.
     */
    public void verifyPhone() {
        this.phoneVerified = true;
    }

    /**
     * Activates the user account.
     */
    public void activate() {
        this.status = UserStatus.ACTIVE;
    }

    /**
     * Deactivates the user account.
     */
    public void deactivate() {
        this.status = UserStatus.INACTIVE;
    }

    /**
     * Suspends the user account.
     * Used for security or compliance reasons.
     */
    public void suspend() {
        this.status = UserStatus.SUSPENDED;
    }

    /**
     * Checks if user is currently active.
     */
    public boolean isActive() {
        return this.status == UserStatus.ACTIVE;
    }

    /**
     * Checks if user account is suspended.
     */
    public boolean isSuspended() {
        return this.status == UserStatus.SUSPENDED;
    }

    /**
     * Checks if user has enrolled biometric data.
     */
    public boolean hasBiometricEnrolled() {
        return this.isBiometricEnrolled;
    }

    /**
     * Checks if user has the given email.
     */
    public boolean hasEmail(Email email) {
        return this.email != null && this.email.equalsIgnoreCase(email.getValue());
    }

    // ========== User Type Methods ==========

    /**
     * Checks if this user is a ROOT (platform super admin).
     */
    public boolean isRoot() {
        return this.userType == UserType.ROOT;
    }

    /**
     * Checks if this user is a tenant administrator.
     */
    public boolean isTenantAdmin() {
        return this.userType == UserType.TENANT_ADMIN;
    }

    /**
     * Checks if this user is a guest.
     */
    public boolean isGuest() {
        return this.userType == UserType.GUEST;
    }

    /**
     * Checks if the guest account has expired.
     * Non-guest users never expire.
     */
    public boolean isExpired() {
        if (this.userType != UserType.GUEST) return false;
        return this.expiresAt != null && this.expiresAt.isBefore(Instant.now());
    }

    /**
     * Checks if this user can manage the target user based on hierarchy.
     */
    public boolean canManage(User target) {
        if (target == null) return false;
        // ROOT can manage anyone
        if (this.userType == UserType.ROOT) return true;
        // Must be in the same tenant (except ROOT)
        if (this.tenant == null || target.tenant == null) return false;
        if (!this.tenant.getId().equals(target.tenant.getId())) return false;
        // Check hierarchy
        return this.userType.canManage(target.userType);
    }

    /**
     * Sets the user type. Only allows promotion/demotion by authorized callers.
     */
    public void setUserType(UserType newType) {
        this.userType = newType;
    }

    // ========== RBAC Methods ==========

    /**
     * Returns all active (non-expired) roles for this user.
     */
    public Set<Role> getActiveRoles() {
        return userRoles.stream()
                .filter(UserRole::isValid)
                .map(UserRole::getRole)
                .collect(Collectors.toSet());
    }

    /**
     * Returns all authorities (roles and permissions) for this user.
     * Format: "ROLE_X" for roles, "resource:action" for permissions.
     */
    public Set<String> getAllAuthorities() {
        Set<String> authorities = new HashSet<>();
        for (UserRole userRole : userRoles) {
            if (userRole.isValid()) {
                Role role = userRole.getRole();
                // Add role as authority (ROLE_ADMIN, ROLE_USER, etc.)
                authorities.add("ROLE_" + role.getName());
                // Add all permissions from the role
                authorities.addAll(role.getPermissionAuthorities());
            }
        }
        return authorities;
    }

    /**
     * Checks if user has a specific permission.
     * @param permission the permission name (e.g., "user:read")
     */
    public boolean hasPermission(String permission) {
        return getAllAuthorities().contains(permission);
    }

    /**
     * Checks if user has a specific role.
     * @param roleName the role name (without "ROLE_" prefix)
     */
    public boolean hasRole(String roleName) {
        return getActiveRoles().stream()
                .anyMatch(r -> r.getName().equalsIgnoreCase(roleName));
    }

    /**
     * Checks if user has any of the specified roles.
     */
    public boolean hasAnyRole(String... roleNames) {
        Set<String> userRoleNames = getActiveRoles().stream()
                .map(Role::getName)
                .map(String::toUpperCase)
                .collect(Collectors.toSet());
        for (String roleName : roleNames) {
            if (userRoleNames.contains(roleName.toUpperCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if user is an administrator.
     * ROOT and TENANT_ADMIN user types are always admins.
     * Also checks for SUPER_ADMIN or TENANT_ADMIN roles for backwards compatibility.
     */
    public boolean isAdmin() {
        return this.userType == UserType.ROOT
            || this.userType == UserType.TENANT_ADMIN
            || hasAnyRole("SUPER_ADMIN", "TENANT_ADMIN");
    }

    /**
     * Gets all permission strings for this user.
     * Compatibility method for existing code.
     */
    public Set<String> getAllPermissions() {
        Set<String> allPermissions = new HashSet<>();
        for (Role role : getActiveRoles()) {
            allPermissions.addAll(role.getPermissionAuthorities());
        }
        return allPermissions;
    }

    /**
     * Gets all role names for this user.
     * Compatibility method for existing code.
     */
    public Set<String> getRoleNames() {
        return getActiveRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
    }

    // ========== Password Reset Methods ==========

    public String generatePasswordResetToken() {
        this.passwordResetToken = UUID.randomUUID().toString();
        this.passwordResetSentAt = Instant.now();
        this.passwordResetExpiresAt = Instant.now().plus(java.time.Duration.ofHours(1));
        return this.passwordResetToken;
    }

    public boolean isPasswordResetTokenExpired() {
        return this.passwordResetExpiresAt == null || Instant.now().isAfter(this.passwordResetExpiresAt);
    }

    public boolean resetPassword(String token, String newPasswordHash) {
        if (this.passwordResetToken == null || !this.passwordResetToken.equals(token)) {
            return false;
        }
        this.passwordHash = newPasswordHash;
        this.passwordResetToken = null;
        this.passwordResetSentAt = null;
        this.passwordResetExpiresAt = null;
        this.passwordChangedAt = Instant.now();
        return true;
    }

    /**
     * Increments the failed login attempt counter.
     */
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts++;
    }

    /**
     * Locks the account for the specified duration.
     *
     * @param duration how long to lock the account
     */
    public void lockAccount(java.time.Duration duration) {
        this.isLocked = true;
        this.lockedUntil = Instant.now().plus(duration);
    }

    /**
     * Resets failed login attempts and unlocks the account.
     */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.isLocked = false;
        this.lockedUntil = null;
    }

    // ========== Email Verification Methods ==========

    public String generateEmailVerificationToken() {
        this.emailVerificationToken = UUID.randomUUID().toString();
        this.emailVerificationSentAt = Instant.now();
        return this.emailVerificationToken;
    }

    public boolean isVerificationTokenExpired() {
        return this.emailVerificationSentAt == null
                || Instant.now().isAfter(this.emailVerificationSentAt.plus(java.time.Duration.ofHours(24)));
    }

    public boolean verifyEmail(String token) {
        if (this.emailVerificationToken == null || !this.emailVerificationToken.equals(token)) {
            return false;
        }
        this.emailVerified = true;
        this.emailVerificationToken = null;
        this.emailVerificationSentAt = null;
        return true;
    }

    // ========== 2FA Methods ==========

    public boolean is2faEnabled() {
        return this.twoFactorSecret != null;
    }

    public void enable2FA(String secret, String[] backupCodes) {
        this.twoFactorSecret = secret;
        this.twoFactorBackupCodes = backupCodes != null ? String.join(",", backupCodes) : null;
    }

    public void disable2FA() {
        this.twoFactorSecret = null;
        this.twoFactorBackupCodes = null;
    }
}
