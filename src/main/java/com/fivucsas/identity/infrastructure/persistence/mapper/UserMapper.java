package com.fivucsas.identity.infrastructure.persistence.mapper;

import com.fivucsas.identity.domain.model.role.Role;
import com.fivucsas.identity.domain.model.user.User;
import com.fivucsas.identity.domain.model.user.UserStatus;
import com.fivucsas.identity.domain.model.user.UserType;
import com.fivucsas.identity.entity.UserRole;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Maps between domain User and JPA User entity.
 * Static utility class - no state, no Spring dependency.
 */
public final class UserMapper {

    private UserMapper() {}

    /**
     * Converts JPA entity to domain model.
     * Includes role mapping from UserRole join entities.
     */
    public static User toDomain(com.fivucsas.identity.entity.User jpa) {
        if (jpa == null) return null;

        // Map roles from UserRole join entity
        Set<Role> domainRoles = null;
        if (jpa.getUserRoles() != null) {
            domainRoles = jpa.getUserRoles().stream()
                .filter(UserRole::isValid)
                .map(ur -> RoleMapper.toDomain(ur.getRole()))
                .collect(Collectors.toSet());
        }

        return User.reconstitute()
            .id(jpa.getId())
            .tenantId(jpa.getTenant() != null ? jpa.getTenant().getId() : null)
            .email(jpa.getEmail())
            .passwordHash(jpa.getPasswordHash())
            .firstName(jpa.getFirstName())
            .lastName(jpa.getLastName())
            .idNumber(jpa.getIdNumber())
            .phoneNumber(jpa.getPhoneNumber())
            .address(jpa.getAddress())
            .status(convertUserStatus(jpa.getStatus()))
            .userType(convertUserType(jpa.getUserType()))
            .expiresAt(jpa.getExpiresAt())
            .invitedById(jpa.getInvitedBy() != null ? jpa.getInvitedBy().getId() : null)
            .emailVerified(jpa.isEmailVerified())
            .emailVerificationToken(jpa.getEmailVerificationToken())
            .emailVerificationSentAt(jpa.getEmailVerificationSentAt())
            .passwordResetToken(jpa.getPasswordResetToken())
            .passwordResetSentAt(jpa.getPasswordResetSentAt())
            .passwordResetExpiresAt(jpa.getPasswordResetExpiresAt())
            .passwordChangedAt(jpa.getPasswordChangedAt())
            .isActive(jpa.isActive())
            .isLocked(jpa.isLocked())
            .lockedUntil(jpa.getLockedUntil())
            .failedLoginAttempts(jpa.getFailedLoginAttempts())
            .lastLoginAt(jpa.getLastLoginAt())
            .lastLoginIp(jpa.getLastLoginIp())
            .phoneVerified(jpa.isPhoneVerified())
            .twoFactorSecret(jpa.getTwoFactorSecret())
            .twoFactorBackupCodes(jpa.getTwoFactorBackupCodes())
            .isBiometricEnrolled(jpa.isBiometricEnrolled())
            .enrolledAt(jpa.getEnrolledAt())
            .lastVerifiedAt(jpa.getLastVerifiedAt())
            .verificationCount(jpa.getVerificationCount())
            .createdAt(jpa.getCreatedAt())
            .updatedAt(jpa.getUpdatedAt())
            .roles(domainRoles)
            .build();
    }

    /**
     * Converts a collection of JPA entities to domain models.
     */
    public static List<User> toDomainList(Collection<com.fivucsas.identity.entity.User> jpaEntities) {
        if (jpaEntities == null) return List.of();
        return jpaEntities.stream()
            .map(UserMapper::toDomain)
            .collect(Collectors.toList());
    }

    // ========== Status/Type Conversion Helpers ==========

    private static UserStatus convertUserStatus(com.fivucsas.identity.entity.UserStatus jpaStatus) {
        if (jpaStatus == null) return UserStatus.ACTIVE;
        return UserStatus.valueOf(jpaStatus.name());
    }

    private static com.fivucsas.identity.entity.UserStatus convertUserStatus(UserStatus domainStatus) {
        if (domainStatus == null) return com.fivucsas.identity.entity.UserStatus.ACTIVE;
        return com.fivucsas.identity.entity.UserStatus.valueOf(domainStatus.name());
    }

    private static UserType convertUserType(com.fivucsas.identity.entity.UserType jpaType) {
        if (jpaType == null) return UserType.TENANT_MEMBER;
        return UserType.valueOf(jpaType.name());
    }

    private static com.fivucsas.identity.entity.UserType convertUserType(UserType domainType) {
        if (domainType == null) return com.fivucsas.identity.entity.UserType.TENANT_MEMBER;
        return com.fivucsas.identity.entity.UserType.valueOf(domainType.name());
    }
}
