package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateAuthFlowCommand;
import com.fivucsas.identity.application.dto.command.UpdateAuthFlowCommand;
import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.port.input.ManageAuthFlowUseCase;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.*;
import com.fivucsas.identity.repository.*;
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

    private static final Set<OperationType> PASSWORD_MANDATORY_OPERATIONS = Set.of(
            OperationType.APP_LOGIN,
            OperationType.API_ACCESS
    );

    private final AuthFlowRepository authFlowRepository;
    private final AuthFlowStepRepository authFlowStepRepository;
    private final AuthMethodRepository authMethodRepository;
    private final TenantRepository tenantRepository;
    private final TenantAuthMethodRepository tenantAuthMethodRepository;

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

        AuthFlow savedFlow = authFlowRepository.save(flow);

        if (command.steps() != null) {
            validatePasswordConstraint(command.operationType(), command.steps());
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

    private void validatePasswordConstraint(OperationType operationType,
                                             List<CreateAuthFlowCommand.FlowStepSpec> steps) {
        if (!PASSWORD_MANDATORY_OPERATIONS.contains(operationType)) {
            return;
        }

        boolean hasPasswordFirst = steps.stream()
                .filter(s -> s.stepOrder() == 1)
                .anyMatch(s -> "PASSWORD".equals(s.authMethodType()));

        if (!hasPasswordFirst) {
            throw new IllegalArgumentException(
                    operationType + " flows must have PASSWORD as the first step");
        }

        log.debug("Password constraint validated for {} flow", operationType);
    }
}
