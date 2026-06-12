package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.AuthMethodResponse;
import com.fivucsas.identity.application.dto.response.TenantAuthMethodResponse;
import com.fivucsas.identity.application.port.input.ManageAuthMethodUseCase;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.TenantAuthMethod;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import com.fivucsas.identity.domain.exception.AuthMethodInUseException;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ManageAuthMethodService implements ManageAuthMethodUseCase {

    private final AuthMethodRepositoryPort authMethodRepository;
    private final TenantAuthMethodRepositoryPort tenantAuthMethodRepository;
    private final JpaTenantRepository tenantRepository;
    private final AuthFlowRepositoryPort authFlowRepository;
    private final PuzzleLayerPolicy puzzleLayerPolicy;

    @Override
    public List<AuthMethodResponse> listAllMethods() {
        // LOGIN methods only: the /auth-methods endpoint backs the tenant
        // Auth-Methods toggles and the auth-flow builder, both of which deal
        // exclusively with login factors. Verification-pipeline step types
        // (DOCUMENT_SCAN, FACE_MATCH, LIVENESS_CHECK, …) have their own config
        // surface (VerificationRepository / VerificationFlowBuilderPage) and
        // must never appear as a selectable LOGIN method. GESTURE_LIVENESS is a
        // FACE liveness sub-component (no handler) and is likewise excluded.
        // PUZZLE is additionally gated by PuzzleLayerPolicy — when the flag is
        // OFF it is suppressed from the catalog even though isLoginMethod()=true.
        return authMethodRepository.findAllByIsActiveTrue().stream()
                .filter(m -> m.getType() != null && m.getType().isLoginMethod())
                .filter(m -> m.getType() != AuthMethodType.PUZZLE || puzzleLayerPolicy.isGloballyEnabled())
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
        // LOGIN methods only — symmetric with listAllMethods(): the tenant
        // Auth-Methods toggle view never shows verification-pipeline step types
        // (so a stale tenant_auth_methods row for a non-login type can't leak
        // into the toggle list). PUZZLE is additionally suppressed when the
        // PuzzleLayerPolicy is not enabled for this tenant.
        return tenantAuthMethodRepository.findAllByTenantId(tenantId).stream()
                .filter(tm -> tm.getAuthMethod() != null
                        && tm.getAuthMethod().getType() != null
                        && tm.getAuthMethod().getType().isLoginMethod())
                .filter(tm -> tm.getAuthMethod().getType() != AuthMethodType.PUZZLE
                        || puzzleLayerPolicy.isEnabledFor(tenantId))
                .map(TenantAuthMethodResponse::from)
                .toList();
    }

    @Override
    @Transactional
    public TenantAuthMethodResponse configureTenantMethod(UUID tenantId, UUID authMethodId, boolean enabled, String config, boolean force) {
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

        // No-lock-out guard (write side): refuse to DISABLE a method that an
        // ACTIVE auth flow still requires — that would let login enforcement
        // block the method an active flow demands and lock users out. The admin
        // can override with force=true (their explicit choice). Enabling is
        // never gated. Only login methods can appear in a login flow, so this is
        // moot for verification-pipeline types.
        if (!enabled && !force) {
            AuthMethodType methodType = tenantMethod.getAuthMethod() != null
                    ? tenantMethod.getAuthMethod().getType() : null;
            if (methodType != null) {
                List<String> dependentActiveFlows = findActiveFlowsRequiringMethod(tenantId, methodType);
                if (!dependentActiveFlows.isEmpty()) {
                    throw new AuthMethodInUseException(methodType.name(), dependentActiveFlows);
                }
            }
        }

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

    /**
     * Names of the tenant's ACTIVE auth flows that reference {@code methodType}
     * in any step (primary, alternative, or fallback). Drives the
     * {@link AuthMethodInUseException} 409 when disabling an in-use method.
     */
    private List<String> findActiveFlowsRequiringMethod(UUID tenantId, AuthMethodType methodType) {
        return authFlowRepository.findAllByTenantId(tenantId).stream()
                .filter(AuthFlow::isActive)
                .filter(flow -> flowReferencesMethod(flow, methodType))
                .map(AuthFlow::getName)
                .toList();
    }

    private boolean flowReferencesMethod(AuthFlow flow, AuthMethodType methodType) {
        for (AuthFlowStep step : flow.getSteps()) {
            boolean inStep = step.getAvailableMethods().stream()
                    .filter(Objects::nonNull)
                    .map(AuthMethod::getType)
                    .anyMatch(t -> t == methodType);
            if (inStep) return true;
            if (step.getFallbackMethod() != null
                    && step.getFallbackMethod().getType() == methodType) {
                return true;
            }
        }
        return false;
    }
}
