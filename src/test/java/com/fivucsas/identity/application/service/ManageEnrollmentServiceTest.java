package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.repository.JpaTenantRepository;
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
class ManageEnrollmentServiceTest {

    @Mock private UserEnrollmentRepositoryPort userEnrollmentRepository;
    @Mock private UserRepository userRepository;
    @Mock private JpaTenantRepository tenantRepository;
    @Mock private BiometricServicePort biometricServicePort;
    @Mock private NfcCardRepositoryPort nfcCardRepository;
    @Mock private WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;

    @InjectMocks
    private ManageEnrollmentService service;

    private final UUID userId = UUID.randomUUID();
    private final UUID tenantId = UUID.randomUUID();

    @Test
    void getUserEnrollments_ShouldReturnMappedResponses() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(enrollment.getId()).thenReturn(UUID.randomUUID());
        when(enrollment.getAuthMethodType()).thenReturn(AuthMethodType.PASSWORD);
        when(enrollment.getStatus()).thenReturn(EnrollmentStatus.ENROLLED);
        when(enrollment.getUser()).thenReturn(null);
        when(enrollment.getTenant()).thenReturn(null);
        when(userEnrollmentRepository.findAllByUserId(userId)).thenReturn(List.of(enrollment));

        // when
        List<EnrollmentResponse> result = service.getUserEnrollments(userId);

        // then
        assertThat(result).hasSize(1);
    }

    @Test
    void startEnrollment_WhenNewEnrollment_ShouldCreateAndComplete() {
        // given
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.PASSWORD))
                .thenReturn(Optional.empty());

        UserEnrollment savedEnrollment = mock(UserEnrollment.class);
        when(savedEnrollment.getId()).thenReturn(UUID.randomUUID());
        when(savedEnrollment.getAuthMethodType()).thenReturn(AuthMethodType.PASSWORD);
        when(savedEnrollment.getStatus()).thenReturn(EnrollmentStatus.ENROLLED);
        when(savedEnrollment.getUser()).thenReturn(null);
        when(savedEnrollment.getTenant()).thenReturn(null);
        when(userEnrollmentRepository.save(any(UserEnrollment.class))).thenReturn(savedEnrollment);

        // when
        EnrollmentResponse result = service.startEnrollment(userId, tenantId, AuthMethodType.PASSWORD);

        // then
        assertThat(result).isNotNull();
        verify(userEnrollmentRepository).save(any(UserEnrollment.class));
    }

    @Test
    void startEnrollment_WhenExistingEnrollment_ShouldReComplete() {
        // given — PASSWORD is in EnrollmentHealthService.AUTO_COMPLETE_TYPES, so
        // re-enrolling an existing PASSWORD enrollment should call completeEnrollment("{}").
        // (TOTP and other async methods call startEnrollment() instead and wait for the
        // real flow to finish via completeEnrollment() with real data.)
        UserEnrollment existing = mock(UserEnrollment.class);
        when(existing.getId()).thenReturn(UUID.randomUUID());
        when(existing.getAuthMethodType()).thenReturn(AuthMethodType.PASSWORD);
        when(existing.getStatus()).thenReturn(EnrollmentStatus.ENROLLED);
        when(existing.getUser()).thenReturn(null);
        when(existing.getTenant()).thenReturn(null);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.PASSWORD))
                .thenReturn(Optional.of(existing));
        when(userEnrollmentRepository.save(existing)).thenReturn(existing);

        // when
        EnrollmentResponse result = service.startEnrollment(userId, tenantId, AuthMethodType.PASSWORD);

        // then
        assertThat(result).isNotNull();
        verify(existing).completeEnrollment("{}");
    }

    @Test
    void startEnrollment_WhenUserNotFound_ShouldThrow() {
        // given
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.PASSWORD))
                .thenReturn(Optional.empty());
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.startEnrollment(userId, tenantId, AuthMethodType.PASSWORD))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    void completeEnrollment_WhenEnrollmentExists_ShouldComplete() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(enrollment.getId()).thenReturn(UUID.randomUUID());
        when(enrollment.getAuthMethodType()).thenReturn(AuthMethodType.FACE);
        when(enrollment.getStatus()).thenReturn(EnrollmentStatus.ENROLLED);
        when(enrollment.getUser()).thenReturn(null);
        when(enrollment.getTenant()).thenReturn(null);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                .thenReturn(Optional.of(enrollment));
        when(userEnrollmentRepository.save(enrollment)).thenReturn(enrollment);

        // when
        EnrollmentResponse result = service.completeEnrollment(userId, AuthMethodType.FACE, "{\"quality\":0.9}");

        // then
        verify(enrollment).completeEnrollment("{\"quality\":0.9}");
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void completeEnrollment_WhenNotFound_ShouldThrow() {
        // given
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.VOICE))
                .thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.completeEnrollment(userId, AuthMethodType.VOICE, "{}"))
                .isInstanceOf(EntityNotFoundException.class);
    }

    @Test
    void revokeEnrollment_WhenBiometricFace_ShouldDeleteBiometricData() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                .thenReturn(Optional.of(enrollment));

        // when
        service.revokeEnrollment(userId, AuthMethodType.FACE);

        // then
        verify(biometricServicePort).deleteFace(userId);
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void revokeEnrollment_WhenBiometricVoice_ShouldDeleteVoiceData() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.VOICE))
                .thenReturn(Optional.of(enrollment));

        // when
        service.revokeEnrollment(userId, AuthMethodType.VOICE);

        // then
        verify(biometricServicePort).deleteVoice(userId);
        verify(enrollment).revoke();
    }

    @Test
    void revokeEnrollment_WhenNonBiometric_ShouldNotCallBiometricService() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.TOTP))
                .thenReturn(Optional.of(enrollment));

        // when
        service.revokeEnrollment(userId, AuthMethodType.TOTP);

        // then
        verifyNoInteractions(biometricServicePort);
        verify(enrollment).revoke();
    }

    @Test
    void revokeEnrollment_WhenBiometricDeleteFails_ShouldStillRevoke() {
        // given
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FINGERPRINT))
                .thenReturn(Optional.of(enrollment));
        doThrow(new RuntimeException("Connection refused"))
                .when(biometricServicePort).deleteFingerprint(userId);

        // when
        service.revokeEnrollment(userId, AuthMethodType.FINGERPRINT);

        // then - enrollment should still be revoked even though biometric delete failed
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void revokeEnrollment_WhenNotFound_ShouldThrow() {
        // given
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.PASSWORD))
                .thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.revokeEnrollment(userId, AuthMethodType.PASSWORD))
                .isInstanceOf(EntityNotFoundException.class);
    }
}
