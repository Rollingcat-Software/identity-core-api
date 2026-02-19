package com.fivucsas.identity.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BiometricRegisterDeviceResponse {
    private String deviceId;
}
