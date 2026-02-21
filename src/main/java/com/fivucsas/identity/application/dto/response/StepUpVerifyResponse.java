package com.fivucsas.identity.application.dto.response;

public record StepUpVerifyResponse(boolean verified, String accessToken, long expiresIn) {}
