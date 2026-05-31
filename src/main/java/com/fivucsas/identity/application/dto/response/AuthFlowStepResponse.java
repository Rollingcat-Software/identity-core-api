package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.domain.model.auth.StepType;

import java.util.List;
import java.util.UUID;

public record AuthFlowStepResponse(
    UUID id,
    int stepOrder,
    AuthMethodResponse authMethod,
    boolean isRequired,
    int timeoutSeconds,
    int maxAttempts,
    AuthMethodResponse fallbackMethod,
    boolean allowsDelegation,
    String config,
    // CHOICE step: the EXTRA methods (besides authMethod) that also satisfy this
    // layer — round-trips the create contract so the builder re-renders the choice
    // on edit. Empty for SEQUENTIAL steps.
    List<String> alternativeMethodTypes
) {
    public static AuthFlowStepResponse from(AuthFlowStep entity) {
        String primaryType = entity.getAuthMethod() != null && entity.getAuthMethod().getType() != null
            ? entity.getAuthMethod().getType().name()
            : null;
        List<String> alternatives = entity.getStepType() == StepType.CHOICE && entity.getAlternativeMethods() != null
            ? entity.getAlternativeMethods().stream()
                // null-guard: an orphaned/unresolved join row leaves a null method —
                // skip it rather than NPE the whole auth-flows list (regression fix).
                .filter(m -> m != null && m.getType() != null)
                .map(m -> m.getType().name())
                .filter(t -> primaryType == null || !t.equals(primaryType))
                .toList()
            : List.of();
        return new AuthFlowStepResponse(
            entity.getId(),
            entity.getStepOrder(),
            AuthMethodResponse.from(entity.getAuthMethod()),
            entity.isRequired(),
            entity.getTimeoutSeconds(),
            entity.getMaxAttempts(),
            entity.getFallbackMethod() != null ? AuthMethodResponse.from(entity.getFallbackMethod()) : null,
            entity.isAllowsDelegation(),
            entity.getConfig(),
            alternatives
        );
    }
}
