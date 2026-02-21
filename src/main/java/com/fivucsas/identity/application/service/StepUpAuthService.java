package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterStepUpDeviceRequest;
import com.fivucsas.identity.application.dto.command.StepUpChallengeRequest;
import com.fivucsas.identity.application.dto.command.StepUpVerifyRequest;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.dto.response.StepUpChallengeResponse;
import com.fivucsas.identity.application.dto.response.StepUpVerifyResponse;
import com.fivucsas.identity.application.port.input.StepUpAuthUseCase;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserDevice;
import com.fivucsas.identity.infrastructure.stepup.StepUpChallengeService;
import com.fivucsas.identity.repository.UserDeviceRepository;
import com.fivucsas.identity.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class StepUpAuthService implements StepUpAuthUseCase {

    private final UserDeviceRepository userDeviceRepository;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final StepUpChallengeService stepUpChallengeService;
    private final TokenGenerationPort tokenGenerationPort;

    @Override
    @Transactional
    public DeviceResponse registerStepUpDevice(UUID userId, UUID tenantId, RegisterStepUpDeviceRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        UserDevice device = userDeviceRepository
                .findByUserIdAndDeviceFingerprint(userId, request.deviceFingerprint())
                .orElseGet(() -> UserDevice.builder()
                        .user(user)
                        .tenant(tenant)
                        .deviceFingerprint(request.deviceFingerprint())
                        .platform(request.platform())
                        .capabilities(request.capabilities() != null ? request.capabilities() : List.of())
                        .build());

        device.updateName(request.deviceName());
        device.registerStepUpKey(request.publicKey(), request.publicKeyAlgorithm());
        device.updateLastUsed();

        log.info("Step-up device registered: userId={}, device={}", userId, request.deviceFingerprint());
        return DeviceResponse.from(userDeviceRepository.save(device));
    }

    @Override
    public StepUpChallengeResponse requestChallenge(UUID userId, StepUpChallengeRequest request) {
        UserDevice device = userDeviceRepository
                .findByUserIdAndDeviceFingerprint(userId, request.deviceFingerprint())
                .orElseThrow(() -> new EntityNotFoundException("Device not found for fingerprint: " + request.deviceFingerprint()));

        if (!device.isStepUpEnabled()) {
            throw new IllegalStateException("Device not registered for step-up authentication");
        }

        String challenge = stepUpChallengeService.generateChallenge(userId, request.deviceFingerprint());
        return new StepUpChallengeResponse(challenge, stepUpChallengeService.getChallengeExpiresInSeconds());
    }

    @Override
    @Transactional
    public StepUpVerifyResponse verifyChallenge(UUID userId, StepUpVerifyRequest request) {
        UserDevice device = userDeviceRepository
                .findByUserIdAndDeviceFingerprint(userId, request.deviceFingerprint())
                .orElseThrow(() -> new EntityNotFoundException("Device not found for fingerprint: " + request.deviceFingerprint()));

        if (!device.isStepUpEnabled()) {
            throw new IllegalStateException("Device not registered for step-up authentication");
        }

        String storedChallenge = stepUpChallengeService.consumeChallenge(userId, request.deviceFingerprint());
        if (storedChallenge == null) {
            throw new IllegalStateException("Challenge expired or not found — request a new challenge");
        }
        if (!storedChallenge.equals(request.challenge())) {
            throw new IllegalArgumentException("Challenge mismatch");
        }

        boolean valid = stepUpChallengeService.verifySignature(
                device.getPublicKey(), request.challenge(), request.signature());

        if (valid) {
            device.updateLastUsed();
            userDeviceRepository.save(device);

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
            String token = tokenGenerationPort.generateAccessToken(user.getEmail());
            long expiresIn = tokenGenerationPort.getExpirationMillis() / 1000;

            log.info("Step-up verification successful: userId={}, device={}", userId, request.deviceFingerprint());
            return new StepUpVerifyResponse(true, token, expiresIn);
        }

        log.warn("Step-up verification failed (invalid signature): userId={}, device={}", userId, request.deviceFingerprint());
        return new StepUpVerifyResponse(false, null, 0);
    }
}
