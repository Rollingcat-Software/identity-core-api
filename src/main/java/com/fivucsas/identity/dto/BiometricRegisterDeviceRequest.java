package com.fivucsas.identity.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class BiometricRegisterDeviceRequest {
    @NotBlank(message = "keyId is required")
    private String keyId;

    @NotBlank(message = "platform is required")
    private String platform;

    @NotNull(message = "publicKeyJwk is required")
    private JsonNode publicKeyJwk;

    private String deviceLabel;
}
