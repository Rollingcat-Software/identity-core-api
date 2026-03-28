package com.fivucsas.identity.domain.model.user;

import com.fivucsas.identity.domain.model.role.Role;
import com.fivucsas.identity.domain.model.tenant.TenantId;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Pure domain model for User aggregate root.
 * No JPA annotations - this is a pure domain concept.
 *
 * Business logic lives here; persistence is handled by infrastructure.
 * Uses value objects (Email, FullName, HashedPassword, etc.) for type safety.
 */
public class User {

    // ========== Identity ==========
    private final UUID id;
    private UUID tenantId;

    // ========== Profile ==========
    private String email;
    private String passwordHash;
    private String firstName;
    private String lastName;
    private String idNumber;
    private String phoneNumber;
    private String address;

    // ========== Status ==========
    private UserStatus status;
    private UserType userType;
    private Instant expiresAt;
    private UUID invitedById;

    // ========== Email Verification ==========
    private boolean emailVerified;
    private String emailVerificationToken;
    private Instant emailVerificationSentAt;

    // ========== Password Reset ==========
    private String passwordResetToken;
    private Instant passwordResetSentAt;
    private Instant passwordResetExpiresAt;
    private Instant passwordChangedAt;

    // ========== Security ==========
    private boolean isActive;
    private boolean isLocked;
    private Instant lockedUntil;
    private int failedLoginAttempts;
    private Instant lastLoginAt;
    private String lastLoginIp;
    private boolean phoneVerified;

    // ========== 2FA ==========
    private String twoFactorSecret;
    private String twoFactorBackupCodes;

    // ========== Biometric ==========
    private boolean isBiometricEnrolled;
    private Instant enrolledAt;
    private Instant lastVerifiedAt;
    private int verificationCount;

    // ========== Timestamps ==========
    private final Instant createdAt;
    private Instant updatedAt;

    // ========== RBAC (transient domain concept) ==========
    private Set<Role> roles;

    private User(Builder builder) {
        this.id = builder.id;
        this.tenantId = builder.tenantId;
        this.email = builder.email;
        this.passwordHash = builder.passwordHash;
        this.firstName = builder.firstName;
        this.lastName = builder.lastName;
        this.idNumber = builder.idNumber;
        this.phoneNumber = builder.phoneNumber;
        this.address = builder.address;
        this.status = builder.status;
        this.userType = builder.userType;
        this.expiresAt = builder.expiresAt;
        this.invitedById = builder.invitedById;
        this.emailVerified = builder.emailVerified;
        this.emailVerificationToken = builder.emailVerificationToken;
        this.emailVerificationSentAt = builder.emailVerificationSentAt;
        this.passwordResetToken = builder.passwordResetToken;
        this.passwordResetSentAt = builder.passwordResetSentAt;
        this.passwordResetExpiresAt = builder.passwordResetExpiresAt;
        this.passwordChangedAt = builder.passwordChangedAt;
        this.isActive = builder.isActive;
        this.isLocked = builder.isLocked;
        this.lockedUntil = builder.lockedUntil;
        this.failedLoginAttempts = builder.failedLoginAttempts;
        this.lastLoginAt = builder.lastLoginAt;
        this.lastLoginIp = builder.lastLoginIp;
        this.phoneVerified = builder.phoneVerified;
        this.twoFactorSecret = builder.twoFactorSecret;
        this.twoFactorBackupCodes = builder.twoFactorBackupCodes;
        this.isBiometricEnrolled = builder.isBiometricEnrolled;
        this.enrolledAt = builder.enrolledAt;
        this.lastVerifiedAt = builder.lastVerifiedAt;
        this.verificationCount = builder.verificationCount;
        this.createdAt = builder.createdAt;
        this.updatedAt = builder.updatedAt;
        this.roles = builder.roles != null ? new HashSet<>(builder.roles) : new HashSet<>();
    }

    // ========== Factory Methods ==========

    /**
     * Creates a new user for registration.
     */
    public static User create(UUID tenantId, String email, String passwordHash,
                              String firstName, String lastName) {
        Objects.requireNonNull(tenantId, "Tenant ID cannot be null");
        Email.of(email); // validate
        FullName.of(firstName, lastName); // validate

        Instant now = Instant.now();
        return builder()
            .tenantId(tenantId)
            .email(email)
            .passwordHash(passwordHash)
            .firstName(firstName)
            .lastName(lastName)
            .status(UserStatus.ACTIVE)
            .userType(UserType.TENANT_MEMBER)
            .isActive(true)
            .isLocked(false)
            .emailVerified(false)
            .phoneVerified(false)
            .isBiometricEnrolled(false)
            .failedLoginAttempts(0)
            .verificationCount(0)
            .createdAt(now)
            .updatedAt(now)
            .build();
    }

    /**
     * Reconstitutes a user from persistence.
     */
    public static Builder reconstitute() {
        return builder();
    }

    public static Builder builder() {
        return new Builder();
    }

    // ========== Value Object Getters (Type-Safe) ==========

    public Email getEmailAsValueObject() {
        return email != null ? Email.of(email) : null;
    }

    public HashedPassword getPasswordAsValueObject() {
        return passwordHash != null ? HashedPassword.of(passwordHash) : null;
    }

    public PhoneNumber getPhoneNumberAsValueObject() {
        return phoneNumber != null ? PhoneNumber.of(phoneNumber) : null;
    }

    public Address getAddressAsValueObject() {
        return address != null ? Address.of(address) : null;
    }

    public IdNumber getIdNumberAsValueObject() {
        return idNumber != null ? IdNumber.of(idNumber) : null;
    }

    public FullName getFullNameAsValueObject() {
        if (firstName == null || lastName == null) return null;
        return FullName.of(firstName, lastName);
    }

    public TenantId getTenantIdAsValueObject() {
        return tenantId != null ? TenantId.of(tenantId) : null;
    }

    // ========== Business Methods ==========

    public String getFullName() {
        FullName fullName = getFullNameAsValueObject();
        return fullName != null ? fullName.getFullName() : "";
    }

    public void changeEmail(Email newEmail) {
        if (newEmail == null) {
            throw new IllegalArgumentException("Email cannot be null");
        }
        this.email = newEmail.getValue();
    }

    public void updatePasswordHash(String newPasswordHash) {
        if (newPasswordHash == null || newPasswordHash.trim().isEmpty()) {
            throw new IllegalArgumentException("Password hash cannot be null or empty");
        }
        this.passwordHash = newPasswordHash;
        this.passwordChangedAt = Instant.now();
    }

    public void updatePhoneNumber(PhoneNumber phoneNumber) {
        this.phoneNumber = phoneNumber != null ? phoneNumber.getValue() : null;
    }

    public void updateAddress(Address address) {
        this.address = address != null ? address.getValue() : null;
    }

    public void updateIdNumber(IdNumber idNumber) {
        this.idNumber = idNumber != null ? idNumber.getValue() : null;
    }

    public void updateProfile(String firstName, String lastName,
                              PhoneNumber phoneNumber, Address address) {
        FullName fullName = FullName.of(firstName, lastName);
        this.firstName = fullName.getFirstName();
        this.lastName = fullName.getLastName();
        this.phoneNumber = phoneNumber != null ? phoneNumber.getValue() : null;
        this.address = address != null ? address.getValue() : null;
    }

    // ========== Biometric Methods ==========

    public void enrollBiometric() {
        this.isBiometricEnrolled = true;
        this.enrolledAt = Instant.now();
    }

    public void unenrollBiometric() {
        this.isBiometricEnrolled = false;
        this.enrolledAt = null;
        this.lastVerifiedAt = null;
        this.verificationCount = 0;
    }

    public void incrementVerificationCount() {
        this.verificationCount++;
        this.lastVerifiedAt = Instant.now();
    }

    public boolean hasBiometricEnrolled() {
        return this.isBiometricEnrolled;
    }

    // ========== Email Verification ==========

    public void verifyEmail() {
        this.emailVerified = true;
        this.emailVerificationToken = null;
        this.emailVerificationSentAt = null;
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

    public String generateEmailVerificationToken() {
        this.emailVerificationToken = UUID.randomUUID().toString();
        this.emailVerificationSentAt = Instant.now();
        return this.emailVerificationToken;
    }

    public boolean isVerificationTokenExpired() {
        return this.emailVerificationSentAt == null
                || Instant.now().isAfter(this.emailVerificationSentAt.plus(Duration.ofHours(24)));
    }

    public void verifyPhone() {
        this.phoneVerified = true;
    }

    // ========== Status Methods ==========

    public void activate() {
        this.status = UserStatus.ACTIVE;
    }

    public void deactivate() {
        this.status = UserStatus.INACTIVE;
    }

    public void suspend() {
        this.status = UserStatus.SUSPENDED;
    }

    public boolean isActive() {
        return this.status == UserStatus.ACTIVE;
    }

    public boolean isSuspended() {
        return this.status == UserStatus.SUSPENDED;
    }

    public boolean hasEmail(Email email) {
        return this.email != null && this.email.equalsIgnoreCase(email.getValue());
    }

    // ========== User Type Methods ==========

    public boolean isRoot() {
        return this.userType == UserType.ROOT;
    }

    public boolean isTenantAdmin() {
        return this.userType == UserType.TENANT_ADMIN;
    }

    public boolean isGuest() {
        return this.userType == UserType.GUEST;
    }

    public boolean isExpired() {
        if (this.userType != UserType.GUEST) return false;
        return this.expiresAt != null && this.expiresAt.isBefore(Instant.now());
    }

    public boolean canManage(User target) {
        if (target == null) return false;
        if (this.userType == UserType.ROOT) return true;
        if (this.tenantId == null || target.tenantId == null) return false;
        if (!this.tenantId.equals(target.tenantId)) return false;
        return this.userType.canManage(target.userType);
    }

    public void setUserType(UserType newType) {
        this.userType = newType;
    }

    // ========== RBAC Methods ==========

    public Set<Role> getActiveRoles() {
        return roles.stream()
                .filter(r -> r.isActive() && !r.isDeleted())
                .collect(Collectors.toSet());
    }

    public Set<String> getAllAuthorities() {
        Set<String> authorities = new HashSet<>();
        for (Role role : getActiveRoles()) {
            authorities.add("ROLE_" + role.getName());
            authorities.addAll(role.getPermissionAuthorities());
        }
        return authorities;
    }

    public boolean hasPermission(String permission) {
        return getAllAuthorities().contains(permission);
    }

    public boolean hasRole(String roleName) {
        return getActiveRoles().stream()
                .anyMatch(r -> r.getName().equalsIgnoreCase(roleName));
    }

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

    public boolean isAdmin() {
        return this.userType == UserType.ROOT
            || this.userType == UserType.TENANT_ADMIN
            || hasAnyRole("SUPER_ADMIN", "TENANT_ADMIN");
    }

    public Set<String> getAllPermissions() {
        Set<String> allPermissions = new HashSet<>();
        for (Role role : getActiveRoles()) {
            allPermissions.addAll(role.getPermissionAuthorities());
        }
        return allPermissions;
    }

    public Set<String> getRoleNames() {
        return getActiveRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles != null ? new HashSet<>(roles) : new HashSet<>();
    }

    // ========== Password Reset Methods ==========

    public String generatePasswordResetToken() {
        this.passwordResetToken = UUID.randomUUID().toString();
        this.passwordResetSentAt = Instant.now();
        this.passwordResetExpiresAt = Instant.now().plus(Duration.ofHours(1));
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

    // ========== Login Security ==========

    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts++;
    }

    public void lockAccount(Duration duration) {
        this.isLocked = true;
        this.lockedUntil = Instant.now().plus(duration);
    }

    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.isLocked = false;
        this.lockedUntil = null;
    }

    public void recordLogin(String ipAddress) {
        this.lastLoginAt = Instant.now();
        this.lastLoginIp = ipAddress;
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

    // ========== Setters for mutable fields ==========

    public void setEmail(String email) { this.email = email; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public void setIdNumber(String idNumber) { this.idNumber = idNumber; }
    public void setPhoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; }
    public void setAddress(String address) { this.address = address; }
    public void setStatus(UserStatus status) { this.status = status; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public void setBiometricEnrolled(boolean enrolled) { this.isBiometricEnrolled = enrolled; }
    public void setEnrolledAt(Instant enrolledAt) { this.enrolledAt = enrolledAt; }

    // ========== Getters ==========

    public UUID getId() { return id; }
    public UUID getTenantId() { return tenantId; }
    public String getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public String getIdNumber() { return idNumber; }
    public String getPhoneNumber() { return phoneNumber; }
    public String getAddress() { return address; }
    public UserStatus getStatus() { return status; }
    public UserType getUserType() { return userType; }
    public Instant getExpiresAt() { return expiresAt; }
    public UUID getInvitedById() { return invitedById; }
    public boolean isEmailVerified() { return emailVerified; }
    public String getEmailVerificationToken() { return emailVerificationToken; }
    public Instant getEmailVerificationSentAt() { return emailVerificationSentAt; }
    public String getPasswordResetToken() { return passwordResetToken; }
    public Instant getPasswordResetSentAt() { return passwordResetSentAt; }
    public Instant getPasswordResetExpiresAt() { return passwordResetExpiresAt; }
    public Instant getPasswordChangedAt() { return passwordChangedAt; }
    public boolean getIsActive() { return isActive; }
    public boolean getIsLocked() { return isLocked; }
    public Instant getLockedUntil() { return lockedUntil; }
    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public Instant getLastLoginAt() { return lastLoginAt; }
    public String getLastLoginIp() { return lastLoginIp; }
    public boolean isPhoneVerified() { return phoneVerified; }
    public String getTwoFactorSecret() { return twoFactorSecret; }
    public String getTwoFactorBackupCodes() { return twoFactorBackupCodes; }
    public boolean isBiometricEnrolled() { return isBiometricEnrolled; }
    public Instant getEnrolledAt() { return enrolledAt; }
    public Instant getLastVerifiedAt() { return lastVerifiedAt; }
    public int getVerificationCount() { return verificationCount; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public Set<Role> getRoles() { return roles != null ? Collections.unmodifiableSet(roles) : Collections.emptySet(); }

    // ========== Builder ==========

    public static final class Builder {
        private UUID id;
        private UUID tenantId;
        private String email;
        private String passwordHash;
        private String firstName;
        private String lastName;
        private String idNumber;
        private String phoneNumber;
        private String address;
        private UserStatus status = UserStatus.ACTIVE;
        private UserType userType = UserType.TENANT_MEMBER;
        private Instant expiresAt;
        private UUID invitedById;
        private boolean emailVerified = false;
        private String emailVerificationToken;
        private Instant emailVerificationSentAt;
        private String passwordResetToken;
        private Instant passwordResetSentAt;
        private Instant passwordResetExpiresAt;
        private Instant passwordChangedAt;
        private boolean isActive = true;
        private boolean isLocked = false;
        private Instant lockedUntil;
        private int failedLoginAttempts = 0;
        private Instant lastLoginAt;
        private String lastLoginIp;
        private boolean phoneVerified = false;
        private String twoFactorSecret;
        private String twoFactorBackupCodes;
        private boolean isBiometricEnrolled = false;
        private Instant enrolledAt;
        private Instant lastVerifiedAt;
        private int verificationCount = 0;
        private Instant createdAt;
        private Instant updatedAt;
        private Set<Role> roles;

        private Builder() {}

        public Builder id(UUID id) { this.id = id; return this; }
        public Builder tenantId(UUID tenantId) { this.tenantId = tenantId; return this; }
        public Builder email(String email) { this.email = email; return this; }
        public Builder passwordHash(String passwordHash) { this.passwordHash = passwordHash; return this; }
        public Builder firstName(String firstName) { this.firstName = firstName; return this; }
        public Builder lastName(String lastName) { this.lastName = lastName; return this; }
        public Builder idNumber(String idNumber) { this.idNumber = idNumber; return this; }
        public Builder phoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; return this; }
        public Builder address(String address) { this.address = address; return this; }
        public Builder status(UserStatus status) { this.status = status; return this; }
        public Builder userType(UserType userType) { this.userType = userType; return this; }
        public Builder expiresAt(Instant expiresAt) { this.expiresAt = expiresAt; return this; }
        public Builder invitedById(UUID invitedById) { this.invitedById = invitedById; return this; }
        public Builder emailVerified(boolean emailVerified) { this.emailVerified = emailVerified; return this; }
        public Builder emailVerificationToken(String token) { this.emailVerificationToken = token; return this; }
        public Builder emailVerificationSentAt(Instant at) { this.emailVerificationSentAt = at; return this; }
        public Builder passwordResetToken(String token) { this.passwordResetToken = token; return this; }
        public Builder passwordResetSentAt(Instant at) { this.passwordResetSentAt = at; return this; }
        public Builder passwordResetExpiresAt(Instant at) { this.passwordResetExpiresAt = at; return this; }
        public Builder passwordChangedAt(Instant at) { this.passwordChangedAt = at; return this; }
        public Builder isActive(boolean isActive) { this.isActive = isActive; return this; }
        public Builder isLocked(boolean isLocked) { this.isLocked = isLocked; return this; }
        public Builder lockedUntil(Instant lockedUntil) { this.lockedUntil = lockedUntil; return this; }
        public Builder failedLoginAttempts(int count) { this.failedLoginAttempts = count; return this; }
        public Builder lastLoginAt(Instant at) { this.lastLoginAt = at; return this; }
        public Builder lastLoginIp(String ip) { this.lastLoginIp = ip; return this; }
        public Builder phoneVerified(boolean verified) { this.phoneVerified = verified; return this; }
        public Builder twoFactorSecret(String secret) { this.twoFactorSecret = secret; return this; }
        public Builder twoFactorBackupCodes(String codes) { this.twoFactorBackupCodes = codes; return this; }
        public Builder isBiometricEnrolled(boolean enrolled) { this.isBiometricEnrolled = enrolled; return this; }
        public Builder enrolledAt(Instant at) { this.enrolledAt = at; return this; }
        public Builder lastVerifiedAt(Instant at) { this.lastVerifiedAt = at; return this; }
        public Builder verificationCount(int count) { this.verificationCount = count; return this; }
        public Builder createdAt(Instant at) { this.createdAt = at; return this; }
        public Builder updatedAt(Instant at) { this.updatedAt = at; return this; }
        public Builder roles(Set<Role> roles) { this.roles = roles; return this; }

        public User build() {
            return new User(this);
        }
    }
}
