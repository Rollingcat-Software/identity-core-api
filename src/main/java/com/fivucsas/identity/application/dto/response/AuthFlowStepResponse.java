package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.entity.AuthFlowStep;

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
    String config
) {
    public static AuthFlowStepResponse from(AuthFlowStep entity) {
        return new AuthFlowStepResponse(
            entity.getId(),
            entity.getStepOrder(),
            AuthMethodResponse.from(entity.getAuthMethod()),
            entity.isRequired(),
            entity.getTimeoutSeconds(),
            entity.getMaxAttempts(),
            entity.getFallbackMethod() != null ? AuthMethodResponse.from(entity.getFallbackMethod()) : null,
            entity.isAllowsDelegation(),
            entity.getConfig()
        );
    }
}
