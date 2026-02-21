package com.fivucsas.identity.application.dto.command;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import jakarta.validation.constraints.NotNull;

public record StartEnrollmentCommand(
    @NotNull AuthMethodType methodType
) {}
