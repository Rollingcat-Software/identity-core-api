package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.repository.JpaTenantRepository;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ManageEnrollmentRevokeTest {

    @Mock private UserEnrollmentRepositoryPort userEnrollmentRepository;
    @Mock private UserRepository userRepository;
    @Mock private JpaTenantRepository tenantRepository;
    @Mock private BiometricServicePort biometricServicePort;
    @Mock private NfcCardRepositoryPort nfcCardRepository;
    @Mock private WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;

    @InjectMocks
    private ManageEnrollmentService service;

    private final UUID userId = UUID.randomUUID();

    // ── Revoke NFC_DOCUMENT: deactivates nfc_cards ──────────────────────

    @Test
    void revokeNfcDocument_ShouldDeactivateActiveCards() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.NFC_DOCUMENT))
                .thenReturn(Optional.of(enrollment));

        NfcCard card1 = mock(NfcCard.class);
        NfcCard card2 = mock(NfcCard.class);
        when(nfcCardRepository.findByUserIdAndIsActiveTrue(userId)).thenReturn(List.of(card1, card2));

        // when
        service.revokeEnrollment(userId, AuthMethodType.NFC_DOCUMENT);

        // then
        verify(card1).deactivate();
        verify(card2).deactivate();
        verify(nfcCardRepository).save(card1);
        verify(nfcCardRepository).save(card2);
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void revokeNfcDocument_WhenNoActiveCards_ShouldStillRevoke() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.NFC_DOCUMENT))
                .thenReturn(Optional.of(enrollment));
        when(nfcCardRepository.findByUserIdAndIsActiveTrue(userId)).thenReturn(Collections.emptyList());

        // when
        service.revokeEnrollment(userId, AuthMethodType.NFC_DOCUMENT);

        // then
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
        verifyNoInteractions(biometricServicePort);
    }

    // ── Revoke FINGERPRINT: deletes platform WebAuthn credentials only ──

    @Test
    void revokeFingerprint_ShouldDeleteOnlyPlatformCredentials() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FINGERPRINT))
                .thenReturn(Optional.of(enrollment));

        UUID platformCredId = UUID.randomUUID();
        UUID crossPlatformCredId = UUID.randomUUID();

        WebAuthnCredential platformCred = mock(WebAuthnCredential.class);
        when(platformCred.getId()).thenReturn(platformCredId);
        when(platformCred.getTransports()).thenReturn("internal");

        WebAuthnCredential crossPlatformCred = mock(WebAuthnCredential.class);
        when(crossPlatformCred.getTransports()).thenReturn("usb");

        when(webAuthnCredentialRepository.findAllByUserId(userId))
                .thenReturn(List.of(platformCred, crossPlatformCred));

        // P1.4: server-side fingerprint biometric was removed (SHA-256 placeholder).
        // FINGERPRINT revocation now ONLY cleans WebAuthn platform credentials,
        // never calls biometricServicePort.

        // when
        service.revokeEnrollment(userId, AuthMethodType.FINGERPRINT);

        // then - only platform ("internal") credential is deleted
        verify(webAuthnCredentialRepository).deleteById(platformCredId);
        verify(webAuthnCredentialRepository, never()).deleteById(crossPlatformCredId);
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void revokeFingerprint_WhenCredentialHasInternalAndUsb_ShouldDeleteIt() {
        // Credential with mixed transports including "internal"
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FINGERPRINT))
                .thenReturn(Optional.of(enrollment));

        UUID credId = UUID.randomUUID();
        WebAuthnCredential mixedCred = mock(WebAuthnCredential.class);
        when(mixedCred.getId()).thenReturn(credId);
        when(mixedCred.getTransports()).thenReturn("internal,usb");

        when(webAuthnCredentialRepository.findAllByUserId(userId))
                .thenReturn(List.of(mixedCred));

        // when
        service.revokeEnrollment(userId, AuthMethodType.FINGERPRINT);

        // then - contains "internal" so it gets deleted
        verify(webAuthnCredentialRepository).deleteById(credId);
        verify(enrollment).revoke();
    }

    @Test
    void revokeFingerprint_WhenNoCredentials_ShouldStillRevoke() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FINGERPRINT))
                .thenReturn(Optional.of(enrollment));
        when(webAuthnCredentialRepository.findAllByUserId(userId)).thenReturn(Collections.emptyList());

        // when
        service.revokeEnrollment(userId, AuthMethodType.FINGERPRINT);

        // then
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    // ── Revoke HARDWARE_KEY: deletes cross-platform credentials only ────

    @Test
    void revokeHardwareKey_ShouldDeleteOnlyCrossPlatformCredentials() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.HARDWARE_KEY))
                .thenReturn(Optional.of(enrollment));

        UUID usbCredId = UUID.randomUUID();
        UUID nfcCredId = UUID.randomUUID();
        UUID platformCredId = UUID.randomUUID();

        WebAuthnCredential usbCred = mock(WebAuthnCredential.class);
        when(usbCred.getId()).thenReturn(usbCredId);
        when(usbCred.getTransports()).thenReturn("usb");

        WebAuthnCredential nfcCred = mock(WebAuthnCredential.class);
        when(nfcCred.getId()).thenReturn(nfcCredId);
        when(nfcCred.getTransports()).thenReturn("nfc");

        WebAuthnCredential platformCred = mock(WebAuthnCredential.class);
        when(platformCred.getTransports()).thenReturn("internal");

        when(webAuthnCredentialRepository.findAllByUserId(userId))
                .thenReturn(List.of(usbCred, nfcCred, platformCred));

        // when
        service.revokeEnrollment(userId, AuthMethodType.HARDWARE_KEY);

        // then - only non-internal credentials are deleted
        verify(webAuthnCredentialRepository).deleteById(usbCredId);
        verify(webAuthnCredentialRepository).deleteById(nfcCredId);
        verify(webAuthnCredentialRepository, never()).deleteById(platformCredId);
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void revokeHardwareKey_WhenCredentialHasNullTransports_ShouldDeleteIt() {
        // Credentials with null transports are treated as cross-platform (not "internal")
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.HARDWARE_KEY))
                .thenReturn(Optional.of(enrollment));

        UUID credId = UUID.randomUUID();
        WebAuthnCredential nullTransportCred = mock(WebAuthnCredential.class);
        when(nullTransportCred.getId()).thenReturn(credId);
        when(nullTransportCred.getTransports()).thenReturn(null);

        when(webAuthnCredentialRepository.findAllByUserId(userId))
                .thenReturn(List.of(nullTransportCred));

        // when
        service.revokeEnrollment(userId, AuthMethodType.HARDWARE_KEY);

        // then - null transports means not "internal", so it gets deleted
        verify(webAuthnCredentialRepository).deleteById(credId);
        verify(enrollment).revoke();
    }

    @Test
    void revokeHardwareKey_WhenBleTransport_ShouldDeleteIt() {
        // BLE is a cross-platform transport
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.HARDWARE_KEY))
                .thenReturn(Optional.of(enrollment));

        UUID credId = UUID.randomUUID();
        WebAuthnCredential bleCred = mock(WebAuthnCredential.class);
        when(bleCred.getId()).thenReturn(credId);
        when(bleCred.getTransports()).thenReturn("ble");

        when(webAuthnCredentialRepository.findAllByUserId(userId))
                .thenReturn(List.of(bleCred));

        // when
        service.revokeEnrollment(userId, AuthMethodType.HARDWARE_KEY);

        // then
        verify(webAuthnCredentialRepository).deleteById(credId);
        verify(enrollment).revoke();
    }

    // ── Revoke TOTP: no extra cleanup needed ────────────────────────────

    @Test
    void revokeTotp_ShouldNotCleanupWebAuthnOrNfcOrBiometric() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.TOTP))
                .thenReturn(Optional.of(enrollment));

        // when
        service.revokeEnrollment(userId, AuthMethodType.TOTP);

        // then
        verifyNoInteractions(biometricServicePort);
        verifyNoInteractions(nfcCardRepository);
        verifyNoInteractions(webAuthnCredentialRepository);
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void revokePassword_ShouldNotCleanupAnything() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.PASSWORD))
                .thenReturn(Optional.of(enrollment));

        // when
        service.revokeEnrollment(userId, AuthMethodType.PASSWORD);

        // then
        verifyNoInteractions(biometricServicePort);
        verifyNoInteractions(nfcCardRepository);
        verifyNoInteractions(webAuthnCredentialRepository);
        verify(enrollment).revoke();
    }

    @Test
    void revokeEmailOtp_ShouldNotCleanupAnything() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.EMAIL_OTP))
                .thenReturn(Optional.of(enrollment));

        // when
        service.revokeEnrollment(userId, AuthMethodType.EMAIL_OTP);

        // then
        verifyNoInteractions(biometricServicePort);
        verifyNoInteractions(nfcCardRepository);
        verifyNoInteractions(webAuthnCredentialRepository);
        verify(enrollment).revoke();
    }

    @Test
    void revokeSmsOtp_ShouldNotCleanupAnything() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.SMS_OTP))
                .thenReturn(Optional.of(enrollment));

        // when
        service.revokeEnrollment(userId, AuthMethodType.SMS_OTP);

        // then
        verifyNoInteractions(biometricServicePort);
        verifyNoInteractions(nfcCardRepository);
        verifyNoInteractions(webAuthnCredentialRepository);
        verify(enrollment).revoke();
    }

    // ── Cleanup failure doesn't block revoke ────────────────────────────

    @Test
    void revokeNfcDocument_WhenCleanupFails_ShouldStillRevoke() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.NFC_DOCUMENT))
                .thenReturn(Optional.of(enrollment));
        when(nfcCardRepository.findByUserIdAndIsActiveTrue(userId))
                .thenThrow(new RuntimeException("DB connection lost"));

        // when
        service.revokeEnrollment(userId, AuthMethodType.NFC_DOCUMENT);

        // then - enrollment should still be revoked
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void revokeHardwareKey_WhenWebAuthnDeleteFails_ShouldStillRevoke() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.HARDWARE_KEY))
                .thenReturn(Optional.of(enrollment));
        when(webAuthnCredentialRepository.findAllByUserId(userId))
                .thenThrow(new RuntimeException("WebAuthn service unavailable"));

        // when
        service.revokeEnrollment(userId, AuthMethodType.HARDWARE_KEY);

        // then - enrollment should still be revoked
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void revokeFingerprint_WhenWebAuthnDeleteFails_ShouldStillRevoke() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FINGERPRINT))
                .thenReturn(Optional.of(enrollment));
        when(webAuthnCredentialRepository.findAllByUserId(userId))
                .thenThrow(new RuntimeException("WebAuthn service unavailable"));

        // P1.4: no biometricServicePort interaction expected (server-side
        // fingerprint biometric was removed). Only WebAuthn cleanup is attempted.

        // when
        service.revokeEnrollment(userId, AuthMethodType.FINGERPRINT);

        // then - enrollment should still be revoked despite cleanup failure
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    // ── Revoke FACE: biometric cleanup ──────────────────────────────────

    @Test
    void revokeFace_WhenBiometricDeleteSucceeds_ShouldRevokeCleanly() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                .thenReturn(Optional.of(enrollment));

        // when
        service.revokeEnrollment(userId, AuthMethodType.FACE);

        // then
        verify(biometricServicePort).deleteFace(userId);
        verifyNoInteractions(nfcCardRepository);
        verifyNoInteractions(webAuthnCredentialRepository);
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void revokeFace_WhenBiometricDeleteFails_ShouldStillRevoke() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                .thenReturn(Optional.of(enrollment));
        doThrow(new RuntimeException("Biometric processor unavailable"))
                .when(biometricServicePort).deleteFace(userId);

        // when
        service.revokeEnrollment(userId, AuthMethodType.FACE);

        // then
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    // ── Revoke VOICE: biometric cleanup ─────────────────────────────────

    @Test
    void revokeVoice_WhenBiometricDeleteFails_ShouldStillRevoke() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.VOICE))
                .thenReturn(Optional.of(enrollment));
        doThrow(new RuntimeException("Biometric processor unavailable"))
                .when(biometricServicePort).deleteVoice(userId);

        // when
        service.revokeEnrollment(userId, AuthMethodType.VOICE);

        // then
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    // ── Enrollment not found ────────────────────────────────────────────

    @Test
    void revokeNfcDocument_WhenNotFound_ShouldThrow() {
        // given
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.NFC_DOCUMENT))
                .thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.revokeEnrollment(userId, AuthMethodType.NFC_DOCUMENT))
                .isInstanceOf(EntityNotFoundException.class);
    }

    @Test
    void revokeHardwareKey_WhenNotFound_ShouldThrow() {
        // given
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.HARDWARE_KEY))
                .thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.revokeEnrollment(userId, AuthMethodType.HARDWARE_KEY))
                .isInstanceOf(EntityNotFoundException.class);
    }
}
