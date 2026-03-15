package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterStepUpDeviceRequest;
import com.fivucsas.identity.application.dto.command.StepUpChallengeRequest;
import com.fivucsas.identity.application.dto.command.StepUpVerifyRequest;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.dto.response.StepUpChallengeResponse;
import com.fivucsas.identity.application.dto.response.StepUpVerifyResponse;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.model.auth.DevicePlatform;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserDevice;
import com.fivucsas.identity.infrastructure.stepup.StepUpChallengeService;
import com.fivucsas.identity.application.port.output.UserDeviceRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StepUpAuthServiceTest {

    @Mock private UserDeviceRepositoryPort userDeviceRepository;
    @Mock private UserRepository userRepository;
    @Mock private TenantRepository tenantRepository;
    @Mock private StepUpChallengeService stepUpChallengeService;
    @Mock private TokenGenerationPort tokenGenerationPort;

    @InjectMocks
    private StepUpAuthService service;

    // --- registerStepUpDevice ---

    @Test
    void registerStepUpDevice_WhenNewDevice_ShouldCreateAndReturnResponse() {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        var request = new RegisterStepUpDeviceRequest(
                "fp-001", DevicePlatform.ANDROID, "pubKey123", "EC_P256", "My Phone", List.of("FINGERPRINT"));

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-001"))
                .thenReturn(Optional.empty());
        when(userDeviceRepository.save(any(UserDevice.class))).thenAnswer(inv -> inv.getArgument(0));

        DeviceResponse result = service.registerStepUpDevice(userId, tenantId, request);

        assertThat(result).isNotNull();
        assertThat(result.deviceFingerprint()).isEqualTo("fp-001");
        assertThat(result.platform()).isEqualTo(DevicePlatform.ANDROID);
        verify(userDeviceRepository).save(any(UserDevice.class));
    }

    @Test
    void registerStepUpDevice_WhenExistingDevice_ShouldUpsertPublicKey() {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        UserDevice existingDevice = mock(UserDevice.class);
        var request = new RegisterStepUpDeviceRequest(
                "fp-001", DevicePlatform.ANDROID, "newPubKey", null, "Updated Phone", null);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-001"))
                .thenReturn(Optional.of(existingDevice));
        when(userDeviceRepository.save(existingDevice)).thenReturn(existingDevice);
        when(existingDevice.getId()).thenReturn(UUID.randomUUID());
        when(existingDevice.getDeviceFingerprint()).thenReturn("fp-001");
        when(existingDevice.getPlatform()).thenReturn(DevicePlatform.ANDROID);
        when(existingDevice.getCapabilities()).thenReturn(List.of());
        when(existingDevice.isTrusted()).thenReturn(false);

        service.registerStepUpDevice(userId, tenantId, request);

        verify(existingDevice).updateName("Updated Phone");
        verify(existingDevice).registerStepUpKey("newPubKey", null);
        verify(existingDevice).updateLastUsed();
        verify(userDeviceRepository).save(existingDevice);
    }

    @Test
    void registerStepUpDevice_WhenUserNotFound_ShouldThrowEntityNotFoundException() {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        var request = new RegisterStepUpDeviceRequest(
                "fp-001", DevicePlatform.ANDROID, "key", null, null, null);

        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.registerStepUpDevice(userId, tenantId, request))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    void registerStepUpDevice_WhenTenantNotFound_ShouldThrowEntityNotFoundException() {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        User user = mock(User.class);
        var request = new RegisterStepUpDeviceRequest(
                "fp-001", DevicePlatform.ANDROID, "key", null, null, null);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.registerStepUpDevice(userId, tenantId, request))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessageContaining("Tenant not found");
    }

    // --- requestChallenge ---

    @Test
    void requestChallenge_WhenDeviceRegistered_ShouldReturnChallenge() {
        UUID userId = UUID.randomUUID();
        var request = new StepUpChallengeRequest("fp-001");
        UserDevice device = mock(UserDevice.class);

        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-001"))
                .thenReturn(Optional.of(device));
        when(device.isStepUpEnabled()).thenReturn(true);
        when(stepUpChallengeService.generateChallenge(userId, "fp-001")).thenReturn("challenge-abc");
        when(stepUpChallengeService.getChallengeExpiresInSeconds()).thenReturn(300L);

        StepUpChallengeResponse result = service.requestChallenge(userId, request);

        assertThat(result.challenge()).isEqualTo("challenge-abc");
        assertThat(result.expiresInSeconds()).isEqualTo(300L);
    }

    @Test
    void requestChallenge_WhenDeviceNotFound_ShouldThrowEntityNotFoundException() {
        UUID userId = UUID.randomUUID();
        var request = new StepUpChallengeRequest("fp-unknown");

        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-unknown"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.requestChallenge(userId, request))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessageContaining("Device not found");
    }

    @Test
    void requestChallenge_WhenDeviceNotStepUpEnabled_ShouldThrowIllegalStateException() {
        UUID userId = UUID.randomUUID();
        var request = new StepUpChallengeRequest("fp-001");
        UserDevice device = mock(UserDevice.class);

        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-001"))
                .thenReturn(Optional.of(device));
        when(device.isStepUpEnabled()).thenReturn(false);

        assertThatThrownBy(() -> service.requestChallenge(userId, request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not registered for step-up");
    }

    // --- verifyChallenge ---

    @Test
    void verifyChallenge_WhenValidSignature_ShouldReturnTokenAndTrue() {
        UUID userId = UUID.randomUUID();
        var request = new StepUpVerifyRequest("fp-001", "challenge-xyz", "sig-valid");
        UserDevice device = mock(UserDevice.class);
        User user = mock(User.class);

        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-001"))
                .thenReturn(Optional.of(device));
        when(device.isStepUpEnabled()).thenReturn(true);
        when(device.getPublicKey()).thenReturn("pubKeyBase64");
        when(stepUpChallengeService.consumeChallenge(userId, "fp-001")).thenReturn("challenge-xyz");
        when(stepUpChallengeService.verifySignature("pubKeyBase64", "challenge-xyz", "sig-valid"))
                .thenReturn(true);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(user.getEmail()).thenReturn("user@test.com");
        when(tokenGenerationPort.generateAccessToken("user@test.com")).thenReturn("jwt-token-123");
        when(tokenGenerationPort.getExpirationMillis()).thenReturn(3600000L);

        StepUpVerifyResponse result = service.verifyChallenge(userId, request);

        assertThat(result.verified()).isTrue();
        assertThat(result.accessToken()).isEqualTo("jwt-token-123");
        assertThat(result.expiresIn()).isEqualTo(3600L);
        verify(device).updateLastUsed();
        verify(userDeviceRepository).save(device);
    }

    @Test
    void verifyChallenge_WhenInvalidSignature_ShouldReturnFalseWithNoToken() {
        UUID userId = UUID.randomUUID();
        var request = new StepUpVerifyRequest("fp-001", "challenge-xyz", "sig-bad");
        UserDevice device = mock(UserDevice.class);

        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-001"))
                .thenReturn(Optional.of(device));
        when(device.isStepUpEnabled()).thenReturn(true);
        when(device.getPublicKey()).thenReturn("pubKeyBase64");
        when(stepUpChallengeService.consumeChallenge(userId, "fp-001")).thenReturn("challenge-xyz");
        when(stepUpChallengeService.verifySignature("pubKeyBase64", "challenge-xyz", "sig-bad"))
                .thenReturn(false);

        StepUpVerifyResponse result = service.verifyChallenge(userId, request);

        assertThat(result.verified()).isFalse();
        assertThat(result.accessToken()).isNull();
        assertThat(result.expiresIn()).isEqualTo(0L);
        verify(device, never()).updateLastUsed();
    }

    @Test
    void verifyChallenge_WhenChallengeExpired_ShouldThrowIllegalStateException() {
        UUID userId = UUID.randomUUID();
        var request = new StepUpVerifyRequest("fp-001", "challenge-xyz", "sig");
        UserDevice device = mock(UserDevice.class);

        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-001"))
                .thenReturn(Optional.of(device));
        when(device.isStepUpEnabled()).thenReturn(true);
        when(stepUpChallengeService.consumeChallenge(userId, "fp-001")).thenReturn(null);

        assertThatThrownBy(() -> service.verifyChallenge(userId, request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Challenge expired");
    }

    @Test
    void verifyChallenge_WhenChallengeMismatch_ShouldThrowIllegalArgumentException() {
        UUID userId = UUID.randomUUID();
        var request = new StepUpVerifyRequest("fp-001", "wrong-challenge", "sig");
        UserDevice device = mock(UserDevice.class);

        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-001"))
                .thenReturn(Optional.of(device));
        when(device.isStepUpEnabled()).thenReturn(true);
        when(stepUpChallengeService.consumeChallenge(userId, "fp-001")).thenReturn("real-challenge");

        assertThatThrownBy(() -> service.verifyChallenge(userId, request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Challenge mismatch");
    }

    @Test
    void verifyChallenge_WhenDeviceNotStepUpEnabled_ShouldThrowIllegalStateException() {
        UUID userId = UUID.randomUUID();
        var request = new StepUpVerifyRequest("fp-001", "challenge", "sig");
        UserDevice device = mock(UserDevice.class);

        when(userDeviceRepository.findByUserIdAndDeviceFingerprint(userId, "fp-001"))
                .thenReturn(Optional.of(device));
        when(device.isStepUpEnabled()).thenReturn(false);

        assertThatThrownBy(() -> service.verifyChallenge(userId, request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not registered for step-up");
    }
}
