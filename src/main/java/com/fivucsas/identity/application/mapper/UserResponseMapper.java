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
     * Stable, descending privilege ordering of known role names. Lower index =
     * higher privilege. Used to pick a DETERMINISTIC primary role from the
     * non-deterministic {@code HashSet} returned by {@code User.getRoleNames()}.
     */
    private static final java.util.List<String> ROLE_PRIVILEGE_ORDER = java.util.List.of(
            "ROOT",
            "SUPER_ADMIN",      // legacy alias of ROOT (pre-V69 rename) — kept for safety
            "TENANT_ADMIN",
            "TENANT_MANAGER",
            "TENANT_EDITOR",
            "TENANT_MEMBER",
            "TENANT_VIEWER",
            "VIEWER",
            "USER",
            "GUEST");

    /**
     * Picks the DETERMINISTIC primary role for a user.
     *
     * <p>Previously this read {@code roleNames.iterator().next()} over a
     * non-deterministic {@code HashSet}, so a multi-role user (e.g. a ROOT who
     * also holds TENANT_ADMIN) could render as either role arbitrarily and the
     * displayed value could flicker between requests. This caused tenant-switcher
     * confusion when a ROOT appeared as "Tenant Admin".
     *
     * <p>Selection is now stable and tier-aware:
     * <ol>
     *   <li>If the user's platform tier is ROOT, prefer the ROOT role when held.</li>
     *   <li>Otherwise pick the highest-privilege known role per
     *       {@link #ROLE_PRIVILEGE_ORDER}.</li>
     *   <li>Any unknown roles (not in the ordering) are ranked last and broken by
     *       alphabetical order, so the result never flickers.</li>
     * </ol>
     *
     * @param roleNames the user's role names (may be empty)
     * @param userTypeName {@code user.getUserType().name()} or {@code null}
     * @return the deterministic primary role, defaulting to {@code "USER"} when empty
     */
    static String resolvePrimaryRole(java.util.Set<String> roleNames, String userTypeName) {
        // Platform tier is AUTHORITATIVE: a ROOT user_type ALWAYS renders as ROOT,
        // even with no (or only lower) assigned role rows. The web already trusts
        // userType (user.isRoot() == userType=='ROOT'); the mobile RBAC
        // (NavigationPolicy) trusts THIS resolved role, so without this a ROOT whose
        // role rows are empty/USER (e.g. promoted via user_type only) is downgraded
        // to USER on mobile — hiding QR-login/admin surfaces it should have. Checked
        // BEFORE the empty-roleNames guard so a ROOT with zero role rows still maps.
        if ("ROOT".equals(userTypeName)) {
            return "ROOT";
        }
        if (roleNames == null || roleNames.isEmpty()) {
            return "USER";
        }
        return roleNames.stream()
                .min(java.util.Comparator
                        .comparingInt(UserResponseMapper::rolePrivilegeRank)
                        .thenComparing(java.util.Comparator.naturalOrder()))
                .orElse("USER");
    }

    /**
     * Rank of a role within {@link #ROLE_PRIVILEGE_ORDER}; unknown roles rank
     * after all known ones (then broken alphabetically by the caller).
     */
    private static int rolePrivilegeRank(String roleName) {
        int idx = ROLE_PRIVILEGE_ORDER.indexOf(roleName);
        return idx >= 0 ? idx : ROLE_PRIVILEGE_ORDER.size();
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
                .role(resolvePrimaryRole(roleNames, user.getUserType() != null ? user.getUserType().name() : null))
                .roles(roleNames.isEmpty() ? java.util.Set.of("USER") : roleNames)
                .userType(user.getUserType() != null ? user.getUserType().name() : null)
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
                .role(resolvePrimaryRole(roleNames, user.getUserType() != null ? user.getUserType().name() : null))
                .roles(roleNames.isEmpty() ? java.util.Set.of("USER") : roleNames)
                .userType(user.getUserType() != null ? user.getUserType().name() : null)
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
