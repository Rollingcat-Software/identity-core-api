package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateTenantCommand;
import com.fivucsas.identity.application.dto.command.UpdateTenantCommand;
import com.fivucsas.identity.application.dto.response.TenantResponse;
import com.fivucsas.identity.application.port.input.ManageTenantUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.DuplicateTenantException;
import com.fivucsas.identity.domain.exception.TenantNotFoundException;
import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.model.tenant.TenantConfiguration;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Use case service for tenant management.
 * Uses pure domain models - no JPA entity references.
 *
 * Implements the ManageTenantUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManageTenantService implements ManageTenantUseCase {

    private final TenantRepository tenantRepository;
    private final com.fivucsas.identity.repository.UserRepository userRepository;
    private final com.fivucsas.identity.repository.TenantEmailDomainRepository tenantEmailDomainRepository;
    private final AuditLogPort auditLogPort;
    private final TenantScopeResolver tenantScopeResolver;
    private final RbacAuthorizationService rbacService;

    /**
     * Resolves the acting admin's user id for audit attribution, or
     * {@code null} when there is no authenticated user (e.g. self-service
     * onboarding via {@code createTenant}). Read off
     * {@link RbacAuthorizationService#getCurrentUserId()} (which returns a
     * {@code UUID}, NOT {@code entity.User}) so this service does not regress
     * the {@code UserDomainBoundaryTest} hexagonal-boundary ratchet.
     */
    private String currentActorId() {
        return rbacService.getCurrentUserId().map(UUID::toString).orElse(null);
    }

    @Override
    @Transactional
    public TenantResponse createTenant(CreateTenantCommand command) {
        log.info("Creating new tenant: {}", command.getName());

        // Validate uniqueness
        if (tenantRepository.existsByName(command.getName())) {
            throw new DuplicateTenantException("name", command.getName());
        }
        if (tenantRepository.existsBySlug(command.getSlug())) {
            throw new DuplicateTenantException("slug", command.getSlug());
        }

        // Build tenant using domain factory method
        Tenant tenant = Tenant.create(
            command.getName(),
            command.getSlug().toLowerCase(),
            command.getDescription(),
            command.getContactEmail(),
            command.getContactPhone()
        );

        // Apply custom configuration if provided
        TenantConfiguration config = TenantConfiguration.of(
            command.getMaxUsers() != null ? command.getMaxUsers() : 100,
            command.getBiometricEnabled() != null ? command.getBiometricEnabled() : true,
            command.getSessionTimeoutMinutes() != null ? command.getSessionTimeoutMinutes() : 30,
            command.getRefreshTokenValidityDays() != null ? command.getRefreshTokenValidityDays() : 7,
            command.getMfaRequired() != null ? command.getMfaRequired() : false
        );
        tenant.updateConfiguration(config);

        tenant = tenantRepository.save(tenant);
        log.info("Tenant created successfully: {}", tenant.getId());

        // P1-4: record the acting admin (actor) DISTINCT from the managed
        // tenant (resource). For self-service onboarding there is no
        // authenticated admin → actorId is null (correct: anonymous/system).
        auditLogPort.logTenantManagementEvent(
                currentActorId(),
                "TENANT_CREATED",
                tenant.getId().toString(),
                String.format("Tenant '%s' (slug=%s) created", tenant.getName(), tenant.getSlug())
        );

        return mapToResponse(tenant);
    }

    @Override
    @Transactional(readOnly = true)
    public TenantResponse getTenantById(String tenantId) {
        log.info("Fetching tenant by id: {}", tenantId);

        UUID uuid = UUID.fromString(tenantId);
        Tenant tenant = tenantRepository.findById(uuid)
            .orElseThrow(() -> new TenantNotFoundException(tenantId));

        return mapToResponse(tenant);
    }

    @Override
    @Transactional(readOnly = true)
    public TenantResponse getTenantBySlug(String slug) {
        log.info("Fetching tenant by slug: {}", slug);

        Tenant tenant = tenantRepository.findBySlug(slug)
            .orElseThrow(() -> new TenantNotFoundException(slug));

        return mapToResponse(tenant);
    }

    @Override
    @Transactional(readOnly = true)
    public List<TenantResponse> getAllTenants() {
        log.info("Fetching all tenants");

        return tenantRepository.findAll().stream()
            .map(t -> mapToResponse(t, false))
            .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public TenantResponse updateTenant(UpdateTenantCommand command) {
        log.info("Updating tenant: {}", command.getTenantId());

        UUID uuid = UUID.fromString(command.getTenantId());

        // S1 — cross-tenant write (IDOR) guard. The controller's
        // @PreAuthorize only checks the 'tenant:configure' permission, which a
        // TENANT_ADMIN holds for their OWN tenant — without this check they
        // could overwrite any other tenant's config by passing its id.
        // canAccessTenant() returns true for SUPER_ADMIN/ROOT (null scope), so
        // root retains cross-tenant access; everyone else is restricted to
        // their own tenant. Mirrors the read-path guard in TenantController and
        // the AccessDeniedException idiom in EnrollmentService (→ 403 via
        // GlobalExceptionHandler).
        if (!tenantScopeResolver.canAccessTenant(uuid)) {
            throw new AccessDeniedException("You do not have permission to update this tenant");
        }

        Tenant tenant = tenantRepository.findById(uuid)
            .orElseThrow(() -> new TenantNotFoundException(command.getTenantId()));

        // Update basic info
        if (command.getName() != null) {
            tenant.updateDetails(command.getName(), command.getDescription());
        }

        // Update contact info
        if (command.getContactEmail() != null) {
            tenant.updateContactInfo(command.getContactEmail(), command.getContactPhone());
        }

        // Update configuration. V64 — defaultMemberRole: null on the command
        // leaves the current value untouched; a blank string clears it (falls
        // back to the seeded baseline role).
        String resolvedDefaultRole = command.getDefaultMemberRole() != null
                ? command.getDefaultMemberRole()
                : tenant.getDefaultMemberRole();
        TenantConfiguration config = TenantConfiguration.of(
            command.getMaxUsers() != null ? command.getMaxUsers() : tenant.getMaxUsers(),
            command.getBiometricEnabled() != null ? command.getBiometricEnabled() : tenant.isBiometricEnabled(),
            command.getSessionTimeoutMinutes() != null ? command.getSessionTimeoutMinutes() : tenant.getSessionTimeoutMinutes(),
            command.getRefreshTokenValidityDays() != null ? command.getRefreshTokenValidityDays() : tenant.getRefreshTokenValidityDays(),
            command.getMfaRequired() != null ? command.getMfaRequired() : tenant.isMfaRequired(),
            command.getEnforceDomainMatching() != null ? command.getEnforceDomainMatching() : tenant.isEnforceDomainMatching(),
            resolvedDefaultRole
        );
        tenant.updateConfiguration(config);

        tenant = tenantRepository.save(tenant);
        log.info("Tenant updated successfully: {}", tenant.getId());

        // #9 (2026-05-21): updateTenant was a silent mutation. Mirror the
        // createTenant() TENANT_CREATED emission with TENANT_UPDATED.
        // P1-4: actor (acting admin) is now DISTINCT from resource (tenant).
        auditLogPort.logTenantManagementEvent(
                currentActorId(),
                "TENANT_UPDATED",
                tenant.getId().toString(),
                String.format("Tenant '%s' (slug=%s) updated", tenant.getName(), tenant.getSlug())
        );

        return mapToResponse(tenant);
    }

    @Override
    @Transactional
    public TenantResponse activateTenant(String tenantId) {
        log.info("Activating tenant: {}", tenantId);

        UUID uuid = UUID.fromString(tenantId);
        Tenant tenant = tenantRepository.findById(uuid)
            .orElseThrow(() -> new TenantNotFoundException(tenantId));

        tenant.activate();
        tenant = tenantRepository.save(tenant);
        log.info("Tenant activated successfully: {}", tenant.getId());

        // #9 (2026-05-21): activateTenant was a silent mutation. Emit
        // TENANT_STATUS_CHANGED (new status carried in details).
        // P1-4: actor (acting admin) is now DISTINCT from resource (tenant).
        auditLogPort.logTenantManagementEvent(
                currentActorId(),
                "TENANT_STATUS_CHANGED",
                tenant.getId().toString(),
                String.format("Tenant '%s' (slug=%s) activated -> %s",
                        tenant.getName(), tenant.getSlug(), tenant.getStatus().name())
        );

        return mapToResponse(tenant);
    }

    @Override
    @Transactional
    public TenantResponse suspendTenant(String tenantId) {
        log.info("Suspending tenant: {}", tenantId);

        UUID uuid = UUID.fromString(tenantId);
        Tenant tenant = tenantRepository.findById(uuid)
            .orElseThrow(() -> new TenantNotFoundException(tenantId));

        tenant.suspend();
        tenant = tenantRepository.save(tenant);
        log.info("Tenant suspended successfully: {}", tenant.getId());

        // #9 (2026-05-21): suspendTenant was a silent mutation. Emit
        // TENANT_STATUS_CHANGED (new status carried in details).
        // P1-4: actor (acting admin) is now DISTINCT from resource (tenant).
        auditLogPort.logTenantManagementEvent(
                currentActorId(),
                "TENANT_STATUS_CHANGED",
                tenant.getId().toString(),
                String.format("Tenant '%s' (slug=%s) suspended -> %s",
                        tenant.getName(), tenant.getSlug(), tenant.getStatus().name())
        );

        return mapToResponse(tenant);
    }

    @Override
    @Transactional
    public void deleteTenant(String tenantId) {
        // Routes through softDeleteTenant — Hibernate's @SQLDelete on the
        // Tenant entity rewrites the SQL to UPDATE...SET deleted_at = NOW()
        // regardless of which path callers take. This wrapper exists so the
        // String-based API stays compatible with existing controllers while
        // the soft-delete contract is documented in one place.
        UUID uuid = UUID.fromString(tenantId);
        softDeleteTenant(uuid);
    }

    @Override
    @Transactional
    public void softDeleteTenant(UUID tenantId) {
        log.info("Soft-deleting tenant: {}", tenantId);

        // Verify the tenant exists and is not already soft-deleted. The
        // findById() call goes through the @SQLRestriction filter, so a
        // soft-deleted row is reported as "not found" (which is the
        // semantically correct behaviour for callers).
        Tenant tenant = tenantRepository.findById(tenantId)
            .orElseThrow(() -> new TenantNotFoundException(tenantId.toString()));

        // deleteById triggers @SQLDelete (UPDATE tenants SET deleted_at = NOW()).
        // No CASCADE is fired because no row is removed.
        tenantRepository.deleteById(tenantId);
        log.info("Tenant soft-deleted successfully: {} "
            + "(child tables intact — cascade chain not triggered)", tenantId);

        // INVESTIGATION_MASTER_2026-05-07 §"audit-log blind spots":
        // emit TENANT_DELETED. We capture the tenant slug+name BEFORE
        // delete (it is still in scope here, the @SQLRestriction filter
        // hides the row from subsequent reads but the in-memory entity
        // is intact for this attribution).
        // P1-4: actor (acting admin) is now DISTINCT from resource (tenant).
        auditLogPort.logTenantManagementEvent(
                currentActorId(),
                "TENANT_DELETED",
                tenantId.toString(),
                String.format("Tenant '%s' (slug=%s) soft-deleted", tenant.getName(), tenant.getSlug())
        );
    }

    private TenantResponse mapToResponse(Tenant tenant) {
        return mapToResponse(tenant, true);
    }

    /**
     * Maps a domain tenant to its response DTO.
     *
     * @param includeEmailDomains when {@code true}, eagerly loads the tenant's
     *        {@code tenant_email_domains} rows so the admin UI can render
     *        current state. The list-all path passes {@code false} to avoid an
     *        N+1 domain query per tenant; single-tenant reads pass {@code true}.
     */
    private TenantResponse mapToResponse(Tenant tenant, boolean includeEmailDomains) {
        long currentUsers = userRepository.countByTenantId(tenant.getId());
        java.util.List<com.fivucsas.identity.application.dto.response.TenantEmailDomainResponse> domains = null;
        if (includeEmailDomains) {
            domains = tenantEmailDomainRepository.findByIdTenantId(tenant.getId()).stream()
                .sorted(java.util.Comparator
                    // primary first, then alphabetical for a stable display order
                    .comparing((com.fivucsas.identity.entity.TenantEmailDomain d) -> !d.isPrimary())
                    .thenComparing(com.fivucsas.identity.entity.TenantEmailDomain::getEmailDomain))
                .map(d -> com.fivucsas.identity.application.dto.response.TenantEmailDomainResponse.builder()
                    .domain(d.getEmailDomain())
                    .isPrimary(d.isPrimary())
                    .createdAt(d.getCreatedAt())
                    .build())
                .collect(Collectors.toList());
        }
        return TenantResponse.builder()
            .id(tenant.getId().toString())
            .name(tenant.getName())
            .slug(tenant.getSlug())
            .description(tenant.getDescription())
            .contactEmail(tenant.getContactEmail())
            .contactPhone(tenant.getContactPhone())
            .status(tenant.getStatus().name())
            .maxUsers(tenant.getMaxUsers())
            .currentUsers((int) currentUsers)
            .biometricEnabled(tenant.isBiometricEnabled())
            .sessionTimeoutMinutes(tenant.getSessionTimeoutMinutes())
            .refreshTokenValidityDays(tenant.getRefreshTokenValidityDays())
            .mfaRequired(tenant.isMfaRequired())
            .enforceDomainMatching(tenant.isEnforceDomainMatching())
            .defaultMemberRole(tenant.getDefaultMemberRole())
            .emailDomains(domains)
            .createdAt(tenant.getCreatedAt())
            .updatedAt(tenant.getUpdatedAt())
            .build();
    }
}
