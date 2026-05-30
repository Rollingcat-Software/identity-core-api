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
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.repository.JpaTenantRepository;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentCaptor.forClass;
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
    @Mock private com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass tenantFilterBypass;

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
        // getUserEnrollments resolves the user-centric read with the tenant filter
        // bypassed; the mock just executes the supplied work.
        when(tenantFilterBypass.runWithoutTenantFilter(any()))
                .thenAnswer(inv -> ((java.util.function.Supplier<?>) inv.getArgument(0)).get());

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

        // then — 3-arg path now delegates to the 5-arg overload with null scores
        verify(enrollment).completeEnrollment("{\"quality\":0.9}", null, null);
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
        // given — use FACE since FINGERPRINT no longer calls biometricServicePort
        // after P1.4 (server-side fingerprint biometric removed; WebAuthn-only).
        UserEnrollment enrollment = mock(UserEnrollment.class);
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                .thenReturn(Optional.of(enrollment));
        doThrow(new RuntimeException("Connection refused"))
                .when(biometricServicePort).deleteFace(userId);

        // when
        service.revokeEnrollment(userId, AuthMethodType.FACE);

        // then - enrollment should still be revoked even though biometric delete failed
        verify(enrollment).revoke();
        verify(userEnrollmentRepository).save(enrollment);
    }

    @Test
    void completeEnrollmentWithScores_ShouldPersistQualityAndLiveness() {
        // given — biometric flow returns quality + liveness scores; the writer
        // must capture them onto the user_enrollments row so the admin
        // Enrollments table can render real numbers instead of "-".
        UserEnrollment enrollment = UserEnrollment.builder()
                .authMethodType(AuthMethodType.FACE)
                .status(EnrollmentStatus.PENDING)
                .build();
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                .thenReturn(Optional.of(enrollment));
        when(userEnrollmentRepository.save(enrollment)).thenReturn(enrollment);

        // when
        EnrollmentResponse result = service.completeEnrollment(
                userId, AuthMethodType.FACE, "{}",
                new BigDecimal("0.9234"), new BigDecimal("0.9501"));

        // then
        ArgumentCaptor<UserEnrollment> captor = forClass(UserEnrollment.class);
        verify(userEnrollmentRepository).save(captor.capture());
        UserEnrollment saved = captor.getValue();
        assertThat(saved.getQualityScore()).isEqualByComparingTo(new BigDecimal("0.9234"));
        assertThat(saved.getLivenessScore()).isEqualByComparingTo(new BigDecimal("0.9501"));
        assertThat(saved.getStatus()).isEqualTo(EnrollmentStatus.ENROLLED);
        assertThat(result.qualityScore()).isEqualTo(0.9234);
        assertThat(result.livenessScore()).isEqualTo(0.9501);
    }

    @Test
    void recordBiometricScores_WhenEnrollmentExists_ShouldUpdateScoresOnly() {
        // given — pre-existing ENROLLED row with a fixed enrolledAt that must
        // not be re-stamped when scores are recorded after the fact.
        java.time.Instant originalEnrolledAt = java.time.Instant.parse("2026-01-01T00:00:00Z");
        UserEnrollment enrollment = UserEnrollment.builder()
                .authMethodType(AuthMethodType.FACE)
                .status(EnrollmentStatus.ENROLLED)
                .enrolledAt(originalEnrolledAt)
                .build();
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                .thenReturn(Optional.of(enrollment));

        // when
        service.recordBiometricScores(userId, AuthMethodType.FACE,
                new BigDecimal("0.8800"), new BigDecimal("0.9100"));

        // then — scores updated, status / enrolledAt unchanged
        ArgumentCaptor<UserEnrollment> captor = forClass(UserEnrollment.class);
        verify(userEnrollmentRepository).save(captor.capture());
        UserEnrollment saved = captor.getValue();
        assertThat(saved.getQualityScore()).isEqualByComparingTo(new BigDecimal("0.8800"));
        assertThat(saved.getLivenessScore()).isEqualByComparingTo(new BigDecimal("0.9100"));
        assertThat(saved.getStatus()).isEqualTo(EnrollmentStatus.ENROLLED);
        assertThat(saved.getEnrolledAt()).isEqualTo(originalEnrolledAt);
    }

    @Test
    void recordBiometricScores_WhenNoEnrollment_ShouldCreatePendingRowWithScores() {
        // P1-3: the web FACE flow records scores during /enroll BEFORE the
        // enrollment row exists (createEnrollment runs afterwards). The writer
        // must now UPSERT — stage a PENDING row (delegating to startEnrollment,
        // using the active TenantContext) and record the scores onto it, instead
        // of silently dropping them.
        TenantContext.setCurrentTenant(tenantId);
        try {
            User user = mock(User.class);
            Tenant tenant = mock(Tenant.class);
            when(userRepository.findById(userId)).thenReturn(Optional.of(user));
            when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

            // findBy: (1) initial upsert probe → empty; (2) startEnrollment probe →
            // empty (builds new row); (3) post-create score write → the saved row.
            UserEnrollment created = UserEnrollment.builder()
                    .authMethodType(AuthMethodType.FACE)
                    .status(EnrollmentStatus.PENDING)
                    .build();
            when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                    .thenReturn(Optional.empty())
                    .thenReturn(Optional.empty())
                    .thenReturn(Optional.of(created));
            when(userEnrollmentRepository.save(any(UserEnrollment.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            service.recordBiometricScores(userId, AuthMethodType.FACE,
                    new BigDecimal("0.5000"), new BigDecimal("0.5000"));

            // the staged row carries PENDING status and the recorded scores
            assertThat(created.getStatus()).isEqualTo(EnrollmentStatus.PENDING);
            assertThat(created.getQualityScore()).isEqualByComparingTo(new BigDecimal("0.5000"));
            assertThat(created.getLivenessScore()).isEqualByComparingTo(new BigDecimal("0.5000"));
        } finally {
            TenantContext.clear();
        }
    }

    @Test
    void recordBiometricScores_WhenNoEnrollmentAndNoTenantContext_ShouldNoOp() {
        // Best-effort: with no row AND no active tenant to anchor the row to, the
        // writer must not throw and must not persist anything.
        TenantContext.clear();
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                .thenReturn(Optional.empty());

        service.recordBiometricScores(userId, AuthMethodType.FACE,
                new BigDecimal("0.5"), new BigDecimal("0.5"));

        verify(userEnrollmentRepository, never()).save(any());
    }

    @Test
    void recordBiometricScores_WhenRowCreationRaces_ShouldStillRecordOntoWinner() {
        // A concurrent enroll/startEnrollment inserts the row between our probe
        // (empty) and startEnrollment's save. startEnrollment catches the
        // unique-constraint violation internally; our follow-up findBy then sees
        // the winner and records the scores onto it.
        TenantContext.setCurrentTenant(tenantId);
        try {
            User user = mock(User.class);
            Tenant tenant = mock(Tenant.class);
            when(userRepository.findById(userId)).thenReturn(Optional.of(user));
            when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

            UserEnrollment winner = UserEnrollment.builder()
                    .authMethodType(AuthMethodType.FACE)
                    .status(EnrollmentStatus.PENDING)
                    .build();
            // probe → empty; startEnrollment initial → empty; startEnrollment
            // race re-fetch → winner; our post-create write → winner.
            when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.FACE))
                    .thenReturn(Optional.empty())
                    .thenReturn(Optional.empty())
                    .thenReturn(Optional.of(winner))
                    .thenReturn(Optional.of(winner));
            when(userEnrollmentRepository.save(any(UserEnrollment.class)))
                    .thenThrow(new DataIntegrityViolationException("duplicate key"))
                    .thenAnswer(inv -> inv.getArgument(0));

            service.recordBiometricScores(userId, AuthMethodType.FACE,
                    new BigDecimal("0.7700"), new BigDecimal("0.8800"));

            assertThat(winner.getQualityScore()).isEqualByComparingTo(new BigDecimal("0.7700"));
            assertThat(winner.getLivenessScore()).isEqualByComparingTo(new BigDecimal("0.8800"));
        } finally {
            TenantContext.clear();
        }
    }

    @Test
    void recordBiometricScores_WhenBothScoresNull_ShouldNoOp() {
        service.recordBiometricScores(userId, AuthMethodType.FACE, null, null);

        verifyNoInteractions(userEnrollmentRepository);
    }

    @Test
    void startEnrollment_WhenSaveRacesUniqueConstraint_ShouldReFetchWinner() {
        // AUDIT_2026-04-28 EDGE-P1 #3: parallel startEnrollment calls collide on the
        // (user_id, auth_method_type) unique constraint. The loser must catch the
        // DataIntegrityViolationException, re-fetch the row committed by the winner,
        // and return idempotently — never surface a 500.
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        UserEnrollment winner = mock(UserEnrollment.class);
        when(winner.getId()).thenReturn(UUID.randomUUID());
        when(winner.getAuthMethodType()).thenReturn(AuthMethodType.TOTP);
        when(winner.getStatus()).thenReturn(EnrollmentStatus.PENDING);
        when(winner.getUser()).thenReturn(null);
        when(winner.getTenant()).thenReturn(null);

        // first findBy returns empty (loser proceeds to build new row),
        // save() throws DataIntegrityViolationException (winner already committed),
        // second findBy returns the winner row.
        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.TOTP))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(winner));
        when(userEnrollmentRepository.save(any(UserEnrollment.class)))
                .thenThrow(new DataIntegrityViolationException(
                        "duplicate key value violates unique constraint"));

        EnrollmentResponse result = service.startEnrollment(userId, tenantId, AuthMethodType.TOTP);

        assertThat(result).isNotNull();
        // findByUserIdAndAuthMethodType called twice: initial lookup + winner re-fetch
        verify(userEnrollmentRepository, times(2))
                .findByUserIdAndAuthMethodType(userId, AuthMethodType.TOTP);
    }

    @Test
    void startEnrollment_WhenSaveRacesAndWinnerVanishes_ShouldRethrow() {
        // Defensive: if the constraint fires but no row is then visible (e.g. row
        // was created and rolled back, or repo bug), we must NOT swallow the
        // exception — surface it so the operator sees a real 500 they can debug.
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        when(userEnrollmentRepository.findByUserIdAndAuthMethodType(userId, AuthMethodType.TOTP))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.empty());
        DataIntegrityViolationException conflict =
                new DataIntegrityViolationException("duplicate key");
        when(userEnrollmentRepository.save(any(UserEnrollment.class))).thenThrow(conflict);

        assertThatThrownBy(() -> service.startEnrollment(userId, tenantId, AuthMethodType.TOTP))
                .isSameAs(conflict);
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
