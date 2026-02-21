package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.RegisterStepUpDeviceRequest;
import com.fivucsas.identity.application.dto.command.StepUpChallengeRequest;
import com.fivucsas.identity.application.dto.command.StepUpVerifyRequest;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.dto.response.StepUpChallengeResponse;
import com.fivucsas.identity.application.dto.response.StepUpVerifyResponse;

import java.util.UUID;

public interface StepUpAuthUseCase {
    DeviceResponse registerStepUpDevice(UUID userId, UUID tenantId, RegisterStepUpDeviceRequest request);
    StepUpChallengeResponse requestChallenge(UUID userId, StepUpChallengeRequest request);
    StepUpVerifyResponse verifyChallenge(UUID userId, StepUpVerifyRequest request);
}
