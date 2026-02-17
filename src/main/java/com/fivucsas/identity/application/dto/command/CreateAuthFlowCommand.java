package com.fivucsas.identity.application.dto.command;

import com.fivucsas.identity.domain.model.auth.OperationType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

public record CreateAuthFlowCommand(
    @NotBlank @Size(max = 100) String name,
    String description,
    @NotNull OperationType operationType,
    boolean isDefault,
    List<FlowStepSpec> steps
) {
    public record FlowStepSpec(
        @NotNull String authMethodType,
        int stepOrder,
        boolean isRequired,
        int timeoutSeconds,
        int maxAttempts,
        String fallbackMethodType,
        boolean allowsDelegation,
        String config
    ) {}
}
