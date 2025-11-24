package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateTenantCommand;
import com.fivucsas.identity.application.dto.command.UpdateTenantCommand;
import com.fivucsas.identity.application.dto.response.TenantResponse;
import com.fivucsas.identity.application.port.input.ManageTenantUseCase;
import com.fivucsas.identity.domain.exception.DuplicateTenantException;
import com.fivucsas.identity.domain.exception.TenantNotFoundException;
import com.fivucsas.identity.domain.model.tenant.TenantConfiguration;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Use case service for tenant management.
 *
 * Implements the ManageTenantUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManageTenantService implements ManageTenantUseCase {

    private final TenantRepository tenantRepository;

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

        // Build tenant entity
        Tenant tenant = Tenant.builder()
            .name(command.getName())
            .slug(command.getSlug().toLowerCase())
            .description(command.getDescription())
            .contactEmail(command.getContactEmail())
            .contactPhone(command.getContactPhone())
            .status(TenantStatus.PENDING)
            .maxUsers(command.getMaxUsers() != null ? command.getMaxUsers() : 100)
            .biometricEnabled(command.getBiometricEnabled() != null ? command.getBiometricEnabled() : true)
            .sessionTimeoutMinutes(command.getSessionTimeoutMinutes() != null ? command.getSessionTimeoutMinutes() : 30)
            .refreshTokenValidityDays(command.getRefreshTokenValidityDays() != null ? command.getRefreshTokenValidityDays() : 7)
            .mfaRequired(command.getMfaRequired() != null ? command.getMfaRequired() : false)
            .build();

        tenant = tenantRepository.save(tenant);
        log.info("Tenant created successfully: {}", tenant.getId());

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
            .map(this::mapToResponse)
            .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public TenantResponse updateTenant(UpdateTenantCommand command) {
        log.info("Updating tenant: {}", command.getTenantId());

        UUID uuid = UUID.fromString(command.getTenantId());
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

        // Update configuration
        TenantConfiguration config = TenantConfiguration.of(
            command.getMaxUsers() != null ? command.getMaxUsers() : tenant.getMaxUsers(),
            command.getBiometricEnabled() != null ? command.getBiometricEnabled() : tenant.isBiometricEnabled(),
            command.getSessionTimeoutMinutes() != null ? command.getSessionTimeoutMinutes() : tenant.getSessionTimeoutMinutes(),
            command.getRefreshTokenValidityDays() != null ? command.getRefreshTokenValidityDays() : tenant.getRefreshTokenValidityDays(),
            command.getMfaRequired() != null ? command.getMfaRequired() : tenant.isMfaRequired()
        );
        tenant.updateConfiguration(config);

        tenant = tenantRepository.save(tenant);
        log.info("Tenant updated successfully: {}", tenant.getId());

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

        return mapToResponse(tenant);
    }

    @Override
    @Transactional
    public void deleteTenant(String tenantId) {
        log.info("Deleting tenant: {}", tenantId);

        UUID uuid = UUID.fromString(tenantId);
        Tenant tenant = tenantRepository.findById(uuid)
            .orElseThrow(() -> new TenantNotFoundException(tenantId));

        tenantRepository.delete(tenant);
        log.info("Tenant deleted successfully: {}", tenantId);
    }

    private TenantResponse mapToResponse(Tenant tenant) {
        return TenantResponse.builder()
            .id(tenant.getId().toString())
            .name(tenant.getName())
            .slug(tenant.getSlug())
            .description(tenant.getDescription())
            .contactEmail(tenant.getContactEmail())
            .contactPhone(tenant.getContactPhone())
            .status(tenant.getStatus().name())
            .maxUsers(tenant.getMaxUsers())
            .biometricEnabled(tenant.isBiometricEnabled())
            .sessionTimeoutMinutes(tenant.getSessionTimeoutMinutes())
            .refreshTokenValidityDays(tenant.getRefreshTokenValidityDays())
            .mfaRequired(tenant.isMfaRequired())
            .createdAt(tenant.getCreatedAt())
            .updatedAt(tenant.getUpdatedAt())
            .build();
    }
}
