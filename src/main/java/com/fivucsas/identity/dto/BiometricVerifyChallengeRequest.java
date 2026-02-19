package com.fivucsas.identity.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class BiometricVerifyChallengeRequest {
    @NotBlank(message = "challengeId is required")
    private String challengeId;

    @NotBlank(message = "keyId is required")
    private String keyId;

    @NotBlank(message = "signatureBase64 is required")
    private String signatureBase64;
}
