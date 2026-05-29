package com.fivucsas.identity.application.mapper;

import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.entity.User;

/**
 * Shared mapper for converting User entities/domain models to UserResponse DTOs.
 *
 * Eliminates the duplicated mapToUserResponse() methods found across
 * RegisterUserService, AuthenticateUserService, and other services.
 *
 * Provides two overloads:
 * - toResponse(entity.User) for services still using JPA entities
 * - fromDomain(domain.model.user.User) for services migrated to domain models
 */
public final class UserResponseMapper {

    private UserResponseMapper() {
        // Utility class
    }

    /**
     * Maps a JPA User entity to UserResponse DTO.
     * Used by services that still work with JPA entities directly.
     */
    public static UserResponse toResponse(User user) {
        var roleNames = user.getRoleNames();
        // P1-4 soft-delete / lazy-proxy guard. A user can outlive its tenant
        // row (tenant soft-deleted — @SQLRestriction hides it, so the lazy
        // Tenant proxy throws EntityNotFoundException when a non-id field like
        // getName() initializes it). Reading getTenant().getId() is FK-safe (no
        // init), but getName() is not. Resolve the tenant name defensively so a
        // single soft-deleted tenant can't 500 the whole user-list render. The
        // tenant_id FK still surfaces. Single getTenant() read into a Tenant
        // local (Tenant is not restricted by UserDomainBoundaryTest).
        com.fivucsas.identity.entity.Tenant tenant = user.getTenant();
        String tenantId = null;
        String tenantName = null;
        if (tenant != null) {
            tenantId = tenant.getId().toString();
            try {
                org.hibernate.Hibernate.initialize(tenant);
                tenantName = tenant.getName();
            } catch (jakarta.persistence.EntityNotFoundException ex) {
                tenantName = null;
            }
        }
        return UserResponse.builder()
                .id(user.getId().toString())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .address(user.getAddress())
                .idNumber(user.getIdNumber() != null ? user.getIdNumberAsValueObject().getMasked() : null)
                .status(user.getStatus().name())
                .emailVerified(user.isEmailVerified())
                .phoneVerified(user.isPhoneVerified())
                .role(roleNames.isEmpty() ? "USER" : roleNames.iterator().next())
                .roles(roleNames.isEmpty() ? java.util.Set.of("USER") : roleNames)
                .tenantId(tenantId)
                .tenantName(tenantName)
                .isBiometricEnrolled(user.isBiometricEnrolled())
                .enrolledAt(user.getEnrolledAt())
                .lastVerifiedAt(user.getLastVerifiedAt())
                .verificationCount(user.getVerificationCount())
                .lastLoginAt(user.getLastLoginAt())
                .lastLoginIp(user.getLastLoginIp())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }

    /**
     * Maps a pure domain User model to UserResponse DTO.
     * Used by services that have been migrated to use domain models.
     *
     * Key difference from toResponse(entity.User):
     * - Uses getTenantId() (UUID) instead of getTenant().getId()
     * - Works with domain value objects directly
     */
    public static UserResponse fromDomain(com.fivucsas.identity.domain.model.user.User user) {
        return fromDomain(user, null);
    }

    /**
     * Maps a pure domain User model to UserResponse DTO, with optional tenant name.
     */
    public static UserResponse fromDomain(com.fivucsas.identity.domain.model.user.User user, String tenantName) {
        var roleNames = user.getRoleNames();
        return UserResponse.builder()
                .id(user.getId().toString())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .address(user.getAddress())
                .idNumber(user.getIdNumber() != null ? user.getIdNumberAsValueObject().getMasked() : null)
                .status(user.getStatus().name())
                .emailVerified(user.isEmailVerified())
                .phoneVerified(user.isPhoneVerified())
                .role(roleNames.isEmpty() ? "USER" : roleNames.iterator().next())
                .roles(roleNames.isEmpty() ? java.util.Set.of("USER") : roleNames)
                .tenantId(user.getTenantId() != null ? user.getTenantId().toString() : null)
                .tenantName(tenantName)
                .isBiometricEnrolled(user.isBiometricEnrolled())
                .enrolledAt(user.getEnrolledAt())
                .lastVerifiedAt(user.getLastVerifiedAt())
                .verificationCount(user.getVerificationCount())
                .lastLoginAt(user.getLastLoginAt())
                .lastLoginIp(user.getLastLoginIp())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }
}
