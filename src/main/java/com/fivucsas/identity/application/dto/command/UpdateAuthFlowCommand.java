package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.Size;

public record UpdateAuthFlowCommand(
    @Size(max = 100) String name,
    String description,
    Boolean isDefault,
    Boolean isActive
) {}
