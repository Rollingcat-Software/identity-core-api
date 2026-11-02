package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.BiometricDeletionOutboxPort;
import com.fivucsas.identity.application.port.output.BiometricDeletionOutboxPort.Method;
import com.fivucsas.identity.application.port.output.BiometricDeletionOutboxPort.PendingDeletion;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.ResourceAccessException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("BiometricDeletionOutboxWorker — drains biometric_deletion_outbox (V87)")
class BiometricDeletionOutboxWorkerTest {

    private static final Instant NOW = Instant.parse("2026-11-02T10:00:00Z");

    @Mock private BiometricDeletionOutboxPort outbox;
    @Mock private BiometricServicePort bio;

    private BiometricDeletionOutboxWorker worker;
    private final UUID userId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        worker = new BiometricDeletionOutboxWorker(outbox, bio, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private PendingDeletion row(Method method, int attempts) {
        return new PendingDeletion(UUID.randomUUID(), userId, UUID.randomUUID(), method, attempts);
    }

    @Test
    @DisplayName("success: FACE and VOICE rows call the matching bio delete and are completed")
    void success_completesBothMethods() {
        PendingDeletion face = row(Method.FACE, 0);
        PendingDeletion voice = row(Method.VOICE, 0);
        when(outbox.findDue(NOW, 10, 50)).thenReturn(List.of(face, voice));
        when(bio.deleteFace(userId)).thenReturn(Map.of("success", true));
        when(bio.deleteVoice(userId)).thenReturn(Map.of("success", true));

        int done = worker.drainOnce();

        assertThat(done).isEqualTo(2);
        verify(outbox).markCompleted(face.id(), NOW);
        verify(outbox).markCompleted(voice.id(), NOW);
        verify(outbox, never()).markFailed(any(), any(), any());
    }

    @Test
    @DisplayName("bio 404 / nothing enrolled (notEnrolled=true) counts as success")
    void notEnrolled_isSuccess() {
        PendingDeletion face = row(Method.FACE, 2);
        when(outbox.findDue(NOW, 10, 50)).thenReturn(List.of(face));
        when(bio.deleteFace(userId)).thenReturn(
                Map.of("success", false, "notEnrolled", true, "message", "No face enrollment found"));

        assertThat(worker.drainOnce()).isEqualTo(1);
        verify(outbox).markCompleted(face.id(), NOW);
        verify(outbox, never()).markFailed(any(), any(), any());
    }

    @Test
    @DisplayName("bio error map → attempt recorded with last_error and exponential backoff")
    void errorMap_recordsFailureWithBackoff() {
        PendingDeletion voice = row(Method.VOICE, 3);
        when(outbox.findDue(NOW, 10, 50)).thenReturn(List.of(voice));
        when(bio.deleteVoice(userId)).thenReturn(
                Map.of("success", false, "message", "Voice deletion service unavailable"));

        assertThat(worker.drainOnce()).isZero();

        // base 60s * 2^3 = 480s
        verify(outbox).markFailed(voice.id(), "Voice deletion service unavailable",
                NOW.plus(Duration.ofSeconds(480)));
        verify(outbox, never()).markCompleted(any(), any());
    }

    @Test
    @DisplayName("exception from the port → failure recorded, other rows still processed")
    void exception_isIsolatedPerRow() {
        PendingDeletion face = row(Method.FACE, 0);
        PendingDeletion voice = row(Method.VOICE, 0);
        when(outbox.findDue(NOW, 10, 50)).thenReturn(List.of(face, voice));
        when(bio.deleteFace(userId)).thenThrow(new ResourceAccessException("connection refused"));
        when(bio.deleteVoice(userId)).thenReturn(Map.of("success", true));

        assertThat(worker.drainOnce()).isEqualTo(1);

        ArgumentCaptor<String> err = ArgumentCaptor.forClass(String.class);
        verify(outbox).markFailed(eq(face.id()), err.capture(), eq(NOW.plus(Duration.ofSeconds(60))));
        assertThat(err.getValue()).contains("ResourceAccessException").contains("connection refused");
        verify(outbox).markCompleted(voice.id(), NOW);
    }

    @Test
    @DisplayName("null response is a failure, not a success")
    void nullResponse_isFailure() {
        PendingDeletion face = row(Method.FACE, 0);
        when(outbox.findDue(NOW, 10, 50)).thenReturn(List.of(face));
        when(bio.deleteFace(userId)).thenReturn(null);

        assertThat(worker.drainOnce()).isZero();
        verify(outbox).markFailed(eq(face.id()), anyString(), any());
    }

    @Test
    @DisplayName("backoff doubles per attempt and is capped at max-backoff")
    void backoff_isExponentialAndCapped() {
        assertThat(worker.backoff(0)).isEqualTo(Duration.ofSeconds(60));
        assertThat(worker.backoff(1)).isEqualTo(Duration.ofSeconds(120));
        assertThat(worker.backoff(5)).isEqualTo(Duration.ofSeconds(1920));
        assertThat(worker.backoff(9)).isEqualTo(Duration.ofHours(6));   // 30720s capped to 21600s
        assertThat(worker.backoff(1000)).isEqualTo(Duration.ofHours(6)); // no overflow
    }

    @Test
    @DisplayName("worker passes the attempt cap to the outbox query (capped retries)")
    void respectsConfiguredMaxAttempts() {
        ReflectionTestUtils.setField(worker, "maxAttempts", 3);
        when(outbox.findDue(NOW, 3, 50)).thenReturn(List.of());

        assertThat(worker.drainOnce()).isZero();
        verify(outbox).findDue(NOW, 3, 50);
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("last allowed attempt failing is still recorded (row parks, no further selection)")
    void finalAttempt_recordsFailure() {
        PendingDeletion face = row(Method.FACE, 9);
        when(outbox.findDue(NOW, 10, 50)).thenReturn(List.of(face));
        when(bio.deleteFace(userId)).thenReturn(Map.of("success", false, "message", "boom"));

        worker.drainOnce();

        verify(outbox).markFailed(face.id(), "boom", NOW.plus(Duration.ofHours(6)));
    }

    @Test
    @DisplayName("idempotent: an empty/drained outbox makes no bio calls")
    void drainedOutbox_isNoOp() {
        when(outbox.findDue(NOW, 10, 50)).thenReturn(List.of());

        assertThat(worker.drainOnce()).isZero();
        assertThat(worker.drainOnce()).isZero();
        verifyNoInteractions(bio);
        verify(outbox, never()).markCompleted(any(), any());
    }

    @Test
    @DisplayName("kill-switch off → scheduled run does not touch the outbox")
    void disabled_skips() {
        ReflectionTestUtils.setField(worker, "enabled", false);

        worker.runScheduled();

        verify(outbox, never()).findDue(any(), anyInt(), anyInt());
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("scheduled entry point is ShedLock-guarded")
    void runScheduled_isShedLocked() throws Exception {
        var m = BiometricDeletionOutboxWorker.class.getMethod("runScheduled");
        assertThat(m.getAnnotation(net.javacrumbs.shedlock.spring.annotation.SchedulerLock.class)).isNotNull();
        assertThat(m.getAnnotation(org.springframework.scheduling.annotation.Scheduled.class)).isNotNull();
    }
}
