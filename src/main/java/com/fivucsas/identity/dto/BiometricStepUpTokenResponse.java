package com.fivucsas.identity.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class BiometricStepUpTokenResponse {
    private String stepUpToken;
    private Instant expiresAt;
}
