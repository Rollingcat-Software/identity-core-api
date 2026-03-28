package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.AuthMethodResponse;
import com.fivucsas.identity.application.dto.response.TenantAuthMethodResponse;
import com.fivucsas.identity.application.port.input.ManageAuthMethodUseCase;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.TenantAuthMethod;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.application.port.output.AuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ManageAuthMethodService implements ManageAuthMethodUseCase {

    private final AuthMethodRepositoryPort authMethodRepository;
    private final TenantAuthMethodRepositoryPort tenantAuthMethodRepository;
    private final JpaTenantRepository tenantRepository;

    @Override
    public List<AuthMethodResponse> listAllMethods() {
        return authMethodRepository.findAllByIsActiveTrue().stream()
                .map(AuthMethodResponse::from)
                .toList();
    }

    @Override
    public AuthMethodResponse getMethodByType(AuthMethodType type) {
        AuthMethod method = authMethodRepository.findByType(type)
                .orElseThrow(() -> new EntityNotFoundException("Auth method not found: " + type));
        return AuthMethodResponse.from(method);
    }

    @Override
    public List<TenantAuthMethodResponse> listTenantMethods(UUID tenantId) {
        return tenantAuthMethodRepository.findAllByTenantId(tenantId).stream()
                .map(TenantAuthMethodResponse::from)
                .toList();
    }

    @Override
    @Transactional
    public TenantAuthMethodResponse configureTenantMethod(UUID tenantId, UUID authMethodId, boolean enabled, String config) {
        TenantAuthMethod tenantMethod = tenantAuthMethodRepository
                .findByTenantIdAndAuthMethodId(tenantId, authMethodId)
                .orElseGet(() -> {
                    Tenant tenant = tenantRepository.findById(tenantId)
                            .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));
                    AuthMethod method = authMethodRepository.findById(authMethodId)
                            .orElseThrow(() -> new EntityNotFoundException("Auth method not found: " + authMethodId));
                    return TenantAuthMethod.builder()
                            .tenant(tenant)
                            .authMethod(method)
                            .build();
                });

        if (enabled) {
            tenantMethod.enable();
        } else {
            tenantMethod.disable();
        }
        if (config != null) {
            tenantMethod.updateConfig(config);
        }

        TenantAuthMethod saved = tenantAuthMethodRepository.save(tenantMethod);
        return TenantAuthMethodResponse.from(saved);
    }
}
