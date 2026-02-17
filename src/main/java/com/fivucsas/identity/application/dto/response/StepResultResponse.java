package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;

import java.util.UUID;

public record StepResultResponse(
    int stepOrder,
    String methodType,
    String stepStatus,
    Integer nextStepOrder,
    AuthSessionStatus sessionStatus,
    AuthenticationResult authentication
) {
    public record AuthenticationResult(
        String accessToken,
        String refreshToken,
        long expiresIn,
        UUID userId
    ) {}
}
