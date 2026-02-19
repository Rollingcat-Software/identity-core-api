package com.fivucsas.identity.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class BiometricChallengeResponse {
    private String challengeId;
    private String nonceBase64;
    private Instant expiresAt;
}
