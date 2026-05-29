package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateAuthFlowCommand;
import com.fivucsas.identity.application.dto.command.UpdateAuthFlowCommand;
import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.port.input.ManageAuthFlowUseCase;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthFlowStepRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthMethodRepositoryPort;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.entity.*;
import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class ManageAuthFlowService implements ManageAuthFlowUseCase {

    private static final Set<String> REQUIRED_UNSUPPORTED_METHODS = Set.of(
            "NFC_DOCUMENT",
            "FINGERPRINT",
            "VOICE"
    );

    private final AuthFlowRepositoryPort authFlowRepository;
    private final AuthFlowStepRepositoryPort authFlowStepRepository;
    private final AuthMethodRepositoryPort authMethodRepository;
    private final JpaTenantRepository tenantRepository;
    private final TenantAuthMethodRepositoryPort tenantAuthMethodRepository;

    @Override
    public List<AuthFlowResponse> listFlows(UUID tenantId, OperationType operationType) {
        List<AuthFlow> flows = operationType != null
                ? authFlowRepository.findAllByTenantIdAndOperationType(tenantId, operationType)
                : authFlowRepository.findAllByTenantId(tenantId);
        return flows.stream().map(AuthFlowResponse::from).toList();
    }

    @Override
    public AuthFlowResponse getFlow(UUID tenantId, UUID flowId) {
        AuthFlow flow = authFlowRepository.findByIdAndTenantId(flowId, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Auth flow not found: " + flowId));
        return AuthFlowResponse.from(flow);
    }

    @Override
    @Transactional
    public AuthFlowResponse createFlow(UUID tenantId, CreateAuthFlowCommand command) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        AuthFlow flow = AuthFlow.builder()
                .tenant(tenant)
                .name(command.name())
                .description(command.description())
                .operationType(command.operationType())
                .isDefault(command.isDefault())
                .build();

        // Reject requests that try to create a flow with no steps at all.
        // Copilot review (PR #18): previously `if (command.steps() != null)` allowed
        // a null steps list through, persisting an unusable empty flow.
        if (command.steps() == null || command.steps().isEmpty()) {
            throw new IllegalArgumentException(
                    "Auth flow must declare at least one step (stepOrder=1 required)");
        }

        AuthFlow savedFlow = authFlowRepository.save(flow);

        {
            validateFirstStepStructure(command.steps());
            validateNoRequiredUnsupportedMethods(command.steps());
            for (CreateAuthFlowCommand.FlowStepSpec stepSpec : command.steps()) {
                AuthMethodType methodType = AuthMethodType.valueOf(stepSpec.authMethodType());
                AuthMethod method = authMethodRepository.findByType(methodType)
                        .orElseThrow(() -> new EntityNotFoundException("Auth method not found: " + stepSpec.authMethodType()));

                AuthMethod fallback = null;
                if (stepSpec.fallbackMethodType() != null && !stepSpec.fallbackMethodType().isEmpty()) {
                    AuthMethodType fallbackType = AuthMethodType.valueOf(stepSpec.fallbackMethodType());
                    fallback = authMethodRepository.findByType(fallbackType).orElse(null);
                }

                AuthFlowStep step = AuthFlowStep.builder()
                        .authFlow(savedFlow)
                        .authMethod(method)
                        .stepOrder(stepSpec.stepOrder())
                        .isRequired(stepSpec.isRequired())
                        .timeoutSeconds(stepSpec.timeoutSeconds() > 0 ? stepSpec.timeoutSeconds() : 120)
                        .maxAttempts(stepSpec.maxAttempts() > 0 ? stepSpec.maxAttempts() : 3)
                        .fallbackMethod(fallback)
                        .allowsDelegation(stepSpec.allowsDelegation())
                        .config(stepSpec.config() != null ? stepSpec.config() : "{}")
                        .build();
                authFlowStepRepository.save(step);
            }
        }

        return AuthFlowResponse.from(authFlowRepository.findById(savedFlow.getId()).orElseThrow());
    }

    @Override
    @Transactional
    public AuthFlowResponse updateFlow(UUID tenantId, UUID flowId, UpdateAuthFlowCommand command) {
        AuthFlow flow = authFlowRepository.findByIdAndTenantId(flowId, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Auth flow not found: " + flowId));

        if (command.name() != null || command.description() != null) {
            flow.updateDetails(
                    command.name() != null ? command.name() : flow.getName(),
                    command.description() != null ? command.description() : flow.getDescription()
            );
        }
        if (command.isDefault() != null && command.isDefault()) {
            // Dethrone the existing default for this (tenant, operationType)
            // pair so the "Default" column always identifies a single flow.
            // Without this, calling setAsDefault here would silently produce
            // two defaults — surprising for the runtime resolver and the
            // admin UI alike.
            //
            // saveAndFlush (not save): the partial unique index
            // uq_auth_flow_default(tenant_id, operation_type) is checked
            // per-statement, not deferred to commit. Hibernate does not
            // guarantee the UPDATE that clears the old default runs before the
            // UPDATE that sets the new one, so a plain save() lets the new
            // default's INSERT/UPDATE hit the index while the old row is still
            // is_default=true → 23505 duplicate-key violation (observed in prod
            // 2026-05-29). Flushing the dethrone first frees the slot.
            authFlowRepository
                    .findAllByTenantIdAndOperationType(tenantId, flow.getOperationType())
                    .stream()
                    .filter(f -> f.isDefault() && !f.getId().equals(flow.getId()))
                    .forEach(f -> {
                        f.unsetDefault();
                        authFlowRepository.saveAndFlush(f);
                    });
            flow.setAsDefault();
        }
        if (command.isActive() != null) {
            if (command.isActive()) flow.activate();
            else flow.deactivate();
        }

        return AuthFlowResponse.from(authFlowRepository.save(flow));
    }

    @Override
    @Transactional
    public void deleteFlow(UUID tenantId, UUID flowId) {
        AuthFlow flow = authFlowRepository.findByIdAndTenantId(flowId, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Auth flow not found: " + flowId));
        authFlowRepository.delete(flow);
    }

    /**
     * Structural validation for the first step of a customizable auth flow.
     *
     * <p>A tenant may choose ANY {@link AuthMethodType} as step[0]; this
     * method no longer enforces PASSWORD-first. What it DOES enforce is that
     * the submitted step list is well-formed:
     *
     * <ul>
     *   <li>non-empty,
     *   <li>contains exactly one step whose {@code stepOrder == 1},
     *   <li>that step declares a parseable {@link AuthMethodType},
     *   <li>and every step has a unique {@code stepOrder}.
     * </ul>
     *
     * Per-step references to concrete {@link AuthMethod} rows and fallbacks
     * are resolved (and validated for existence) in {@link #createFlow}
     * below. DB-level range constraints live in V16/V30.
     */
    private void validateFirstStepStructure(List<CreateAuthFlowCommand.FlowStepSpec> steps) {
        if (steps.isEmpty()) {
            throw new IllegalArgumentException("Auth flow must define at least one step");
        }

        long stepOneCount = steps.stream().filter(s -> s.stepOrder() == 1).count();
        if (stepOneCount == 0) {
            throw new IllegalArgumentException("Auth flow must define a step with stepOrder=1");
        }
        if (stepOneCount > 1) {
            throw new IllegalArgumentException("Auth flow has multiple steps with stepOrder=1");
        }

        CreateAuthFlowCommand.FlowStepSpec firstStep = steps.stream()
                .filter(s -> s.stepOrder() == 1)
                .findFirst()
                .orElseThrow();

        if (firstStep.authMethodType() == null || firstStep.authMethodType().isBlank()) {
            throw new IllegalArgumentException("First step must reference an AuthMethod");
        }
        try {
            AuthMethodType.valueOf(firstStep.authMethodType());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(
                    "First step references unknown AuthMethod: " + firstStep.authMethodType(), ex);
        }

        long uniqueOrders = steps.stream().map(CreateAuthFlowCommand.FlowStepSpec::stepOrder).distinct().count();
        if (uniqueOrders != steps.size()) {
            throw new IllegalArgumentException("Auth flow steps must have unique stepOrder values");
        }

        log.debug("First-step structural check passed (method={}, {} step(s))",
                firstStep.authMethodType(), steps.size());
    }

    private void validateNoRequiredUnsupportedMethods(List<CreateAuthFlowCommand.FlowStepSpec> steps) {
        List<String> requiredUnsupportedMethods = steps.stream()
                .filter(CreateAuthFlowCommand.FlowStepSpec::isRequired)
                .map(CreateAuthFlowCommand.FlowStepSpec::authMethodType)
                .filter(REQUIRED_UNSUPPORTED_METHODS::contains)
                .distinct()
                .toList();

        if (!requiredUnsupportedMethods.isEmpty()) {
            throw new IllegalArgumentException(
                    "The following methods cannot be configured as required auth steps yet: " +
                    requiredUnsupportedMethods +
                    ". These flows rely on hardware/biometric integrations that are not fully available. " +
                    "Configure them as optional steps or choose a different method.");
        }
    }
}
