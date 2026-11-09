package com.fivucsas.identity.security;

import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/**
 * Single source of the tenant a biometric template is stored under in the
 * biometric-processor: the tenant of the user being enrolled (issue #284).
 *
 * <p>Every enroll endpoint (face image, face multi-image, face embedding, voice
 * embedding) resolves its tenant here, and {@code EnrollmentHealthService} probes
 * with the same value ({@code UserRepository.findTenantIdById}), so the stored row
 * and the login probe always name the same partition. A client {@code tenant_id}
 * is no longer trusted: it may not move a template into another tenant, and when
 * it is absent the template is no longer stored tenant-less.</p>
 *
 * <p>Cross-tenant guard: enrolling another user requires access to that user's
 * tenant ({@link RbacAuthorizationService#canAccessTenant(UUID)}: same tenant, or
 * ROOT). A tenant-less subject can be enrolled by itself or by ROOT only. The
 * subject lookup runs without the Hibernate tenant filter so that the decision is
 * made here explicitly and not by an incidental filter scope (for example a ROOT
 * enrolling itself while browsing another tenant).</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class BiometricEnrollmentTenantResolver {

    private final UserRepository userRepository;
    private final RbacAuthorizationService rbacService;
    private final TenantFilterBypass tenantFilterBypass;

    /**
     * @param subjectUserId     the user whose template is enrolled
     * @param requestedTenantId the optional client {@code tenant_id}; logged when it
     *                          disagrees, never used
     * @return the subject's tenant id, or {@code null} for a tenant-less user
     * @throws UserNotFoundException when the subject does not exist
     * @throws AccessDeniedException when the caller may not act in the subject's tenant
     */
    public String resolve(UUID subjectUserId, String requestedTenantId) {
        UUID subjectTenant = tenantFilterBypass.runWithoutTenantFilter(() -> lookUpTenant(subjectUserId))
                .orElse(null);

        boolean self = rbacService.getCurrentUserId().map(subjectUserId::equals).orElse(false);
        if (!self && !mayEnrollIn(subjectTenant)) {
            log.warn("Refused biometric enroll for user {}: caller may not act in tenant {}",
                    subjectUserId, subjectTenant);
            throw new AccessDeniedException("You may not enroll biometrics for a user of another tenant");
        }

        String tenantId = subjectTenant != null ? subjectTenant.toString() : null;
        if (requestedTenantId != null && !requestedTenantId.isBlank()
                && !requestedTenantId.trim().equalsIgnoreCase(String.valueOf(tenantId))) {
            log.warn("Ignoring tenant_id {} on biometric enroll for user {}: the user's tenant is {}",
                    requestedTenantId, subjectUserId, tenantId);
        }
        return tenantId;
    }

    private Optional<UUID> lookUpTenant(UUID subjectUserId) {
        Optional<UUID> tenant = userRepository.findTenantIdById(subjectUserId);
        if (tenant.isEmpty() && !userRepository.existsById(subjectUserId)) {
            throw new UserNotFoundException(subjectUserId.toString());
        }
        return tenant;
    }

    private boolean mayEnrollIn(UUID subjectTenant) {
        return subjectTenant != null ? rbacService.canAccessTenant(subjectTenant) : rbacService.isRoot();
    }
}
