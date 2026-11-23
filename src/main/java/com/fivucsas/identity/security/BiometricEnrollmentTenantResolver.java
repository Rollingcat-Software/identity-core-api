package com.fivucsas.identity.security;

import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Single source of the tenant a biometric template is stored under in the
 * biometric-processor, and of the cross-tenant guard for every biometric enroll
 * (issue #284).
 *
 * <p>Every endpoint that stores a face template (face image, face multi-image,
 * face embedding, legacy {@code /api/v1/enrollment/submit}) and the voice
 * embedding enroll resolve their tenant here: the tenant of the user being
 * enrolled. {@code EnrollmentHealthService} probes with the same value
 * ({@code UserRepository.findTenantIdById}), so the stored row and the login
 * probe always name the same partition. A client {@code tenant_id} is not
 * trusted: it may not move a template into another tenant, and when it is
 * absent the template is not stored tenant-less. The legacy voice enroll, whose
 * bio store is not tenant-scoped, calls {@link #assertMayEnroll(UUID)} for the
 * guard alone.</p>
 *
 * <p>Cross-tenant guard: enrolling another user requires access to that user's
 * tenant ({@link RbacAuthorizationService#canAccessTenant(UUID)}: same tenant, or
 * ROOT). A tenant-less subject can be enrolled by itself or by ROOT only. "Self"
 * is decided by {@link UserSecurityService#isCurrentUser(UUID)}, the predicate
 * the endpoints' {@code @PreAuthorize} uses, so the two never disagree. An
 * unknown subject is 404 for ROOT only; any other caller gets the same 403 as
 * for a user of a foreign tenant, so user ids of other tenants cannot be
 * probed. The subject lookup runs without the Hibernate tenant filter so that
 * the decision is made here explicitly and not by an incidental filter scope
 * (for example a ROOT enrolling itself while browsing another tenant).</p>
 *
 * <p>Both public methods open a read-only transaction: {@link TenantFilterBypass}
 * needs one, and the resolver must not depend on open-in-view.</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class BiometricEnrollmentTenantResolver {

    private final UserRepository userRepository;
    private final RbacAuthorizationService rbacService;
    private final UserSecurityService userSecurityService;
    private final TenantFilterBypass tenantFilterBypass;

    /**
     * @param subjectUserId     the user whose template is enrolled
     * @param requestedTenantId the optional client {@code tenant_id}; logged when it
     *                          disagrees, never used
     * @return the subject's tenant id, or {@code null} for a tenant-less user
     * @throws UserNotFoundException when ROOT names a user that does not exist
     * @throws AccessDeniedException when the caller may not enroll the subject
     */
    @Transactional(readOnly = true)
    public String resolve(UUID subjectUserId, String requestedTenantId) {
        UUID subjectTenant = authorize(subjectUserId);

        String tenantId = subjectTenant != null ? subjectTenant.toString() : null;
        if (requestedTenantId != null && !requestedTenantId.isBlank()
                && !requestedTenantId.trim().equalsIgnoreCase(String.valueOf(tenantId))) {
            log.warn("Ignoring tenant_id {} on biometric enroll for user {}: the user's tenant is {}",
                    requestedTenantId, subjectUserId, tenantId);
        }
        return tenantId;
    }

    /**
     * The cross-tenant guard of {@link #resolve} without the tenant, for an enroll
     * whose bio store is not tenant-scoped (legacy voice enroll).
     *
     * @throws UserNotFoundException when ROOT names a user that does not exist
     * @throws AccessDeniedException when the caller may not enroll the subject
     */
    @Transactional(readOnly = true)
    public void assertMayEnroll(UUID subjectUserId) {
        authorize(subjectUserId);
    }

    /** @return the subject's tenant ({@code null} for a tenant-less user) once the caller may enroll it */
    private UUID authorize(UUID subjectUserId) {
        Subject subject = tenantFilterBypass.runWithoutTenantFilter(() -> lookUp(subjectUserId));

        if (!subject.exists()) {
            if (rbacService.isRoot()) {
                throw new UserNotFoundException(subjectUserId.toString());
            }
            throw refuse(subjectUserId, "unknown user");
        }
        boolean self = userSecurityService.isCurrentUser(subjectUserId);
        if (!self && !mayEnrollIn(subject.tenantId())) {
            throw refuse(subjectUserId, "user of tenant " + subject.tenantId());
        }
        return subject.tenantId();
    }

    private Subject lookUp(UUID subjectUserId) {
        Optional<UUID> tenant = userRepository.findTenantIdById(subjectUserId);
        if (tenant.isPresent()) {
            return new Subject(true, tenant.get());
        }
        return new Subject(userRepository.existsById(subjectUserId), null);
    }

    private boolean mayEnrollIn(UUID subjectTenant) {
        return subjectTenant != null ? rbacService.canAccessTenant(subjectTenant) : rbacService.isRoot();
    }

    private static AccessDeniedException refuse(UUID subjectUserId, String reason) {
        log.warn("Refused biometric enroll for user {}: caller may not act on this subject ({})",
                subjectUserId, reason);
        return new AccessDeniedException("You may not enroll biometrics for this user");
    }

    /** The enrolled user as seen without the tenant filter. */
    private record Subject(boolean exists, UUID tenantId) {
    }
}
