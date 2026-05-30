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
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.application.dto.response.AuthFlowDefaultImpactResponse;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
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
    private final UserEnrollmentRepositoryPort userEnrollmentRepository;
    private final com.fivucsas.identity.repository.UserRepository userRepository;

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

    @Override
    @Transactional(readOnly = true)
    public AuthFlowDefaultImpactResponse computeDefaultImpact(UUID tenantId, UUID flowId) {
        AuthFlow flow = authFlowRepository.findByIdAndTenantId(flowId, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Auth flow not found: " + flowId));

        // Each requirement = the set of methods that satisfy one required step.
        // SEQUENTIAL → size 1; CHOICE → the alternatives (user needs >=1).
        // PASSWORD is always available so it never constitutes a lockout risk.
        // Usernameless factors (PASSKEY/APPROVE_LOGIN/QR_CODE) likewise never
        // count as a lockout risk (task #16 F): the factor proves its own
        // enrollment, so requiring it cannot strand a user the way an
        // un-enrolled OTP/biometric step can — they're excluded from the
        // requirement set exactly like PASSWORD.
        Set<AuthMethodType> usernamelessTypes = usernamelessMethodTypes();
        List<Set<AuthMethodType>> requirements = new java.util.ArrayList<>();
        boolean hasPasswordStep = false;
        boolean everyRequiredStepIsSoleUsernameless = true;
        boolean hasRequiredStep = false;
        for (AuthFlowStep step : flow.getSteps()) {
            if (!step.isRequired()) continue;
            hasRequiredStep = true;
            List<AuthMethodType> stepTypes = step.getAvailableMethods().stream()
                    .map(AuthMethod::getType).toList();
            if (stepTypes.contains(AuthMethodType.PASSWORD)) hasPasswordStep = true;
            // A step provides recovery breadth unless it is a SINGLE usernameless
            // factor with no alternative.
            boolean soleUsernameless = stepTypes.size() == 1
                    && usernamelessTypes.contains(stepTypes.get(0));
            if (!soleUsernameless) everyRequiredStepIsSoleUsernameless = false;

            Set<AuthMethodType> opts = stepTypes.stream()
                    .filter(m -> m != AuthMethodType.PASSWORD)
                    .filter(m -> !usernamelessTypes.contains(m))
                    .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
            if (!opts.isEmpty()) requirements.add(opts);
        }

        // No usable recovery: the flow has no PASSWORD step and every required
        // step is a single usernameless factor with no alternative — losing the
        // device locks the user out with no fallback (task #16 F).
        boolean noRecoveryWarning =
                hasRequiredStep && !hasPasswordStep && everyRequiredStepIsSoleUsernameless;

        List<UUID> activeUserIds = userRepository.findIdsByTenantId(tenantId);
        long activeUsers = activeUserIds.size();

        // Enrolled methods per user (ENROLLED status only).
        java.util.Map<UUID, Set<AuthMethodType>> enrolledByUser = new java.util.HashMap<>();
        for (UserEnrollment e : userEnrollmentRepository.findAllByTenantId(tenantId)) {
            if (e.getStatus() == EnrollmentStatus.ENROLLED && e.getUserId() != null) {
                enrolledByUser
                        .computeIfAbsent(e.getUserId(), k -> java.util.EnumSet.noneOf(AuthMethodType.class))
                        .add(e.getAuthMethodType());
            }
        }

        // A user is "at risk" if they fail to satisfy at least one requirement.
        long usersAtRisk = activeUserIds.stream().filter(uid -> {
            Set<AuthMethodType> have = enrolledByUser.getOrDefault(uid, Set.of());
            return requirements.stream().anyMatch(req -> req.stream().noneMatch(have::contains));
        }).count();

        // Per-method coverage for every distinct required method.
        Set<AuthMethodType> choiceMethods = requirements.stream()
                .filter(r -> r.size() > 1).flatMap(Set::stream)
                .collect(java.util.stream.Collectors.toSet());
        Set<AuthMethodType> allRequired = requirements.stream().flatMap(Set::stream)
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));

        List<AuthFlowDefaultImpactResponse.MethodCoverage> coverage = allRequired.stream().map(m -> {
            long enrolled = activeUserIds.stream()
                    .filter(uid -> enrolledByUser.getOrDefault(uid, Set.of()).contains(m))
                    .count();
            return new AuthFlowDefaultImpactResponse.MethodCoverage(
                    m.name(), choiceMethods.contains(m), enrolled, activeUsers - enrolled);
        }).toList();

        return new AuthFlowDefaultImpactResponse(
                flow.getId().toString(), flow.getName(), flow.getOperationType().name(),
                activeUsers, usersAtRisk, coverage, noRecoveryWarning);
    }

    /**
     * The set of {@link AuthMethodType}s flagged supports_usernameless in
     * auth_methods. Used by {@link #computeDefaultImpact} to exclude
     * usernameless factors from lockout-risk accounting (task #16 F). Resolved
     * from the DB so it stays in sync with the V73 seed rather than hardcoding
     * the list in two places.
     */
    private Set<AuthMethodType> usernamelessMethodTypes() {
        return authMethodRepository.findAllByIsActiveTrue().stream()
                .filter(AuthMethod::isSupportsUsernameless)
                .map(AuthMethod::getType)
                .collect(java.util.stream.Collectors.toCollection(
                        () -> java.util.EnumSet.noneOf(AuthMethodType.class)));
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
