package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.model.user.User;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("BiometricEnrollmentReconciler Tests")
class BiometricEnrollmentReconcilerTest {

    @Mock
    private UserDomainRepository userDomainRepository;

    @Mock
    private BiometricServicePort biometricServicePort;

    @InjectMocks
    private BiometricEnrollmentReconciler reconciler;

    private UUID tenantId;
    private UUID enrolledInBioId;     // flag=false BUT has a real bio embedding → must repair
    private UUID notEnrolledInBioId;  // flag=false AND no bio embedding → must NOT touch

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        enrolledInBioId = UUID.randomUUID();
        notEnrolledInBioId = UUID.randomUUID();
    }

    private User userWithFlag(UUID id, boolean enrolled) {
        return User.builder()
            .id(id)
            .tenantId(tenantId)
            .email(id + "@example.com")
            .isBiometricEnrolled(enrolled)
            .build();
    }

    @Test
    @DisplayName("Dry-run returns the count that WOULD change and writes nothing")
    void dryRunCountsButDoesNotWrite() {
        User repairable = userWithFlag(enrolledInBioId, false);
        User leaveAlone = userWithFlag(notEnrolledInBioId, false);
        when(userDomainRepository.findByIsBiometricEnrolled(false))
            .thenReturn(List.of(repairable, leaveAlone));
        when(biometricServicePort.hasEnrollment(enrolledInBioId, tenantId.toString())).thenReturn(true);
        when(biometricServicePort.hasEnrollment(notEnrolledInBioId, tenantId.toString())).thenReturn(false);

        var result = reconciler.reconcile(true);

        assertThat(result.dryRun()).isTrue();
        assertThat(result.scanned()).isEqualTo(2);
        assertThat(result.wouldUpdate()).isEqualTo(1);
        assertThat(result.updated()).isZero();
        assertThat(result.affectedIds()).containsExactly(enrolledInBioId);
        // Dry-run writes NOTHING
        verify(userDomainRepository, never()).save(any());
        assertThat(repairable.hasBiometricEnrolled()).isFalse();
    }

    @Test
    @DisplayName("Apply flips the flag ONLY for users with a confirmed bio enrollment")
    void applyFlipsOnlyConfirmed() {
        User repairable = userWithFlag(enrolledInBioId, false);
        User leaveAlone = userWithFlag(notEnrolledInBioId, false);
        when(userDomainRepository.findByIsBiometricEnrolled(false))
            .thenReturn(List.of(repairable, leaveAlone));
        when(biometricServicePort.hasEnrollment(enrolledInBioId, tenantId.toString())).thenReturn(true);
        when(biometricServicePort.hasEnrollment(notEnrolledInBioId, tenantId.toString())).thenReturn(false);
        when(userDomainRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        var result = reconciler.reconcile(false);

        assertThat(result.dryRun()).isFalse();
        assertThat(result.scanned()).isEqualTo(2);
        assertThat(result.updated()).isEqualTo(1);
        assertThat(result.affectedIds()).containsExactly(enrolledInBioId);
        // Only the confirmed user is flipped + saved
        assertThat(repairable.hasBiometricEnrolled()).isTrue();
        assertThat(leaveAlone.hasBiometricEnrolled()).isFalse();
        verify(userDomainRepository, times(1)).save(repairable);
        verify(userDomainRepository, never()).save(leaveAlone);
    }

    @Test
    @DisplayName("Idempotent: a second apply over an already-repaired population changes nothing")
    void idempotentSecondRun() {
        // After the first repair, the user's flag is true, so the reconciler no
        // longer even sees it (findByIsBiometricEnrolled(false) excludes it).
        when(userDomainRepository.findByIsBiometricEnrolled(false)).thenReturn(List.of());

        var result = reconciler.reconcile(false);

        assertThat(result.scanned()).isZero();
        assertThat(result.updated()).isZero();
        assertThat(result.affectedIds()).isEmpty();
        verify(userDomainRepository, never()).save(any());
        verify(biometricServicePort, never()).hasEnrollment(any(), any());
    }

    @Test
    @DisplayName("Fail-closed: a user the bio store cannot confirm is NOT flipped")
    void failClosedOnUnconfirmed() {
        User uncertain = userWithFlag(enrolledInBioId, false);
        when(userDomainRepository.findByIsBiometricEnrolled(false)).thenReturn(List.of(uncertain));
        // Port already fails closed (returns false) on bio error.
        when(biometricServicePort.hasEnrollment(enrolledInBioId, tenantId.toString())).thenReturn(false);

        var result = reconciler.reconcile(false);

        assertThat(result.updated()).isZero();
        assertThat(uncertain.hasBiometricEnrolled()).isFalse();
        verify(userDomainRepository, never()).save(any());
    }

    @Test
    @DisplayName("A thrown hasEnrollment for one user does not abort the whole pass")
    void oneThrowingUserDoesNotAbortPass() {
        User throwsForThis = userWithFlag(notEnrolledInBioId, false);
        User repairable = userWithFlag(enrolledInBioId, false);
        when(userDomainRepository.findByIsBiometricEnrolled(false))
            .thenReturn(List.of(throwsForThis, repairable));
        when(biometricServicePort.hasEnrollment(notEnrolledInBioId, tenantId.toString()))
            .thenThrow(new RuntimeException("bio blip"));
        when(biometricServicePort.hasEnrollment(enrolledInBioId, tenantId.toString())).thenReturn(true);
        when(userDomainRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        var result = reconciler.reconcile(false);

        // The throwing user is skipped; the healthy one is still repaired.
        assertThat(result.updated()).isEqualTo(1);
        assertThat(result.affectedIds()).containsExactly(enrolledInBioId);
        verify(userDomainRepository, times(1)).save(repairable);
    }

    @Test
    @DisplayName("Null tenant on the user is forwarded as null to the bio port")
    void nullTenantForwardedAsNull() {
        User noTenant = User.builder()
            .id(enrolledInBioId)
            .email("x@example.com")
            .isBiometricEnrolled(false)
            .build();
        when(userDomainRepository.findByIsBiometricEnrolled(false)).thenReturn(List.of(noTenant));
        when(biometricServicePort.hasEnrollment(eq(enrolledInBioId), eq(null))).thenReturn(true);
        when(userDomainRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        var result = reconciler.reconcile(false);

        assertThat(result.updated()).isEqualTo(1);
        verify(biometricServicePort).hasEnrollment(enrolledInBioId, null);
    }
}
