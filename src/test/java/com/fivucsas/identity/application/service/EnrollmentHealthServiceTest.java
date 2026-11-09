package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.port.output.UserDeviceRepositoryPort;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.application.service.transaction.TrackingTransactionManager;
import com.fivucsas.identity.application.service.transaction.TransactionRunner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the real biometric enrollment-probe in EnrollmentHealthService
 * (login triage F2/F7/F9). The previous behaviour FAKED FACE/VOICE as
 * always-enrolled whenever the bio service was reachable, routing un-enrolled
 * users into a VOICE step that could never pass. These tests pin the tri-state
 * probe + the kill-switch.
 */
@ExtendWith(MockitoExtension.class)
class EnrollmentHealthServiceTest {

    @Mock private UserEnrollmentRepositoryPort userEnrollmentRepository;
    @Mock private UserRepository userRepository;
    @Mock private WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;
    @Mock private UserDeviceRepositoryPort userDeviceRepository;
    @Mock private NfcCardRepositoryPort nfcCardRepository;
    @Mock private StringRedisTemplate redisTemplate;
    @Mock private BiometricServicePort biometricServicePort;
    @Mock private com.fivucsas.identity.repository.UserRepository userJpaRepository;

    private final UUID userId = UUID.randomUUID();
    private final TrackingTransactionManager transactionManager = new TrackingTransactionManager();

    private EnrollmentHealthService service(boolean probeEnabled) {
        return new EnrollmentHealthService(
                userEnrollmentRepository, userRepository, webAuthnCredentialRepository,
                userDeviceRepository, nfcCardRepository, redisTemplate, biometricServicePort,
                new TransactionRunner(transactionManager), userJpaRepository,
                /* crossMembershipNfcEnabled */ false,
                /* enrollmentProbeEnabled   */ probeEnabled);
    }

    private void givenUserWithEnrollment(AuthMethodType type) {
        User user = User.builder().id(userId).email("u@marun.edu.tr")
                .firstName("A").lastName("B").build();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        UserEnrollment enrollment = UserEnrollment.builder()
                .id(UUID.randomUUID())
                .authMethodType(type)
                .status(EnrollmentStatus.ENROLLED)
                .build();
        when(userEnrollmentRepository.findAllByUserId(userId)).thenReturn(List.of(enrollment));
        // Stale rows are re-read by id in the revoke transaction.
        lenient().when(userEnrollmentRepository.findById(enrollment.getId())).thenReturn(Optional.of(enrollment));
    }

    // -- Connection use (#285) --------------------------------------------------

    @Test
    void validateEnrollments_WhenBiometricProbeRuns_ShouldHoldNoTransaction() {
        givenUserWithEnrollment(AuthMethodType.FACE);
        when(userJpaRepository.findTenantIdById(userId)).thenReturn(Optional.empty());
        java.util.List<Integer> openDuringProbe = new java.util.ArrayList<>();
        when(biometricServicePort.faceEnrollmentExists(userId, null)).thenAnswer(invocation -> {
            openDuringProbe.add(transactionManager.openTransactions());
            return Boolean.FALSE;
        });

        Map<AuthMethodType, Boolean> health = service(true).validateEnrollments(userId);

        assertThat(health.get(AuthMethodType.FACE)).isFalse();
        assertThat(openDuringProbe).containsExactly(0);
        // read transaction, then the separate revoke transaction for the stale row
        assertThat(transactionManager.events()).containsExactly("begin", "commit", "begin", "commit");
        verify(userEnrollmentRepository).save(any(UserEnrollment.class));
    }

    @Test
    void validateEnrollments_WhenCallerHoldsATransaction_ShouldReadInItsOwnIsolatedTransaction() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(User.builder().id(userId)
                .email("u@marun.edu.tr").firstName("A").lastName("B").build()));
        when(userJpaRepository.findTenantIdById(userId)).thenReturn(Optional.empty());
        when(biometricServicePort.faceEnrollmentExists(userId, null)).thenReturn(Boolean.TRUE);
        java.util.List<Integer> openDuringRead = new java.util.ArrayList<>();
        when(userEnrollmentRepository.findAllByUserId(userId)).thenAnswer(invocation -> {
            openDuringRead.add(transactionManager.openTransactions());
            return List.of(UserEnrollment.builder().id(UUID.randomUUID())
                    .authMethodType(AuthMethodType.FACE).status(EnrollmentStatus.ENROLLED).build());
        });
        EnrollmentHealthService service = service(true);

        Map<AuthMethodType, Boolean> health = new TransactionRunner(transactionManager)
                .inTransaction(effects -> service.validateEnrollments(userId));

        assertThat(health.get(AuthMethodType.FACE)).isTrue();
        // The read neither sees nor poisons the caller's uncommitted work: it runs in
        // its own transaction on top of the caller's, as the former REQUIRES_NEW did.
        assertThat(openDuringRead).containsExactly(2);
        assertThat(transactionManager.events()).containsExactly("begin", "begin", "commit", "commit");
    }

    // -- VOICE -----------------------------------------------------------------

    @Test
    void voice_definitiveFalse_reportsNotEnrolled_andAutoRevokes() {
        givenUserWithEnrollment(AuthMethodType.VOICE);
        when(biometricServicePort.voiceEnrollmentExists(userId)).thenReturn(Boolean.FALSE);

        Map<AuthMethodType, Boolean> health = service(true).validateEnrollments(userId);

        // The un-enrolled VOICE method is reported NOT usable (the core F2/F7 fix)
        assertThat(health.get(AuthMethodType.VOICE)).isFalse();
        // ... and the stale ENROLLED row is auto-revoked.
        verify(userEnrollmentRepository).save(any(UserEnrollment.class));
        verify(biometricServicePort).voiceEnrollmentExists(userId);
    }

    @Test
    void voice_definitiveTrue_reportsEnrolled_noRevoke() {
        givenUserWithEnrollment(AuthMethodType.VOICE);
        when(biometricServicePort.voiceEnrollmentExists(userId)).thenReturn(Boolean.TRUE);

        Map<AuthMethodType, Boolean> health = service(true).validateEnrollments(userId);

        assertThat(health.get(AuthMethodType.VOICE)).isTrue();
        verify(userEnrollmentRepository, never()).save(any(UserEnrollment.class));
    }

    @Test
    void voice_unknownOnOutage_failsOpen_noRevoke() {
        givenUserWithEnrollment(AuthMethodType.VOICE);
        // null = UNKNOWN (transport/5xx) → fail OPEN so an outage never locks out.
        when(biometricServicePort.voiceEnrollmentExists(userId)).thenReturn(null);

        Map<AuthMethodType, Boolean> health = service(true).validateEnrollments(userId);

        assertThat(health.get(AuthMethodType.VOICE)).isTrue();
        verify(userEnrollmentRepository, never()).save(any(UserEnrollment.class));
    }

    // -- FACE ------------------------------------------------------------------

    @Test
    void face_definitiveTrue_stillPasses_forGenuinelyEnrolledUser() {
        // CRITICAL: the working face flow must NOT break — a genuine enrollment
        // must still resolve to enrolled=true.
        givenUserWithEnrollment(AuthMethodType.FACE);
        UUID tenantId = UUID.randomUUID();
        when(userJpaRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));
        when(biometricServicePort.faceEnrollmentExists(userId, tenantId.toString()))
                .thenReturn(Boolean.TRUE);

        Map<AuthMethodType, Boolean> health = service(true).validateEnrollments(userId);

        assertThat(health.get(AuthMethodType.FACE)).isTrue();
        verify(userEnrollmentRepository, never()).save(any(UserEnrollment.class));
        // Face probe is tenant-scoped (verify-path parity).
        verify(biometricServicePort).faceEnrollmentExists(userId, tenantId.toString());
    }

    @Test
    void face_definitiveFalse_reportsNotEnrolled() {
        givenUserWithEnrollment(AuthMethodType.FACE);
        when(userJpaRepository.findTenantIdById(userId)).thenReturn(Optional.empty());
        when(biometricServicePort.faceEnrollmentExists(userId, null)).thenReturn(Boolean.FALSE);

        Map<AuthMethodType, Boolean> health = service(true).validateEnrollments(userId);

        assertThat(health.get(AuthMethodType.FACE)).isFalse();
        verify(userEnrollmentRepository).save(any(UserEnrollment.class));
    }

    // -- Kill-switch -----------------------------------------------------------

    @Test
    void killSwitchOff_revertsToLegacyTrustIfReachable_noProbe() {
        givenUserWithEnrollment(AuthMethodType.VOICE);
        lenient().when(biometricServicePort.checkHealth())
                .thenReturn(Map.of("status", "ok"));

        Map<AuthMethodType, Boolean> health = service(false).validateEnrollments(userId);

        // Legacy: enrolled trusted, no existence probe is ever issued.
        assertThat(health.get(AuthMethodType.VOICE)).isTrue();
        verify(biometricServicePort, never()).voiceEnrollmentExists(any());
        verify(biometricServicePort, never()).faceEnrollmentExists(any(), any());
        verify(userEnrollmentRepository, never()).save(any(UserEnrollment.class));
    }
}
