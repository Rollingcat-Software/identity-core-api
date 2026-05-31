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
        List<String> alternatives = entity.getStepType() == StepType.CHOICE && entity.getAlternativeMethods() != null
            ? entity.getAlternativeMethods().stream()
                .map(m -> m.getType().name())
                .filter(t -> entity.getAuthMethod() == null || !t.equals(entity.getAuthMethod().getType().name()))
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
