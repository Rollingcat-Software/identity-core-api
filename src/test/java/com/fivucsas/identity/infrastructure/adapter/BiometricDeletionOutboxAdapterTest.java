package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.BiometricDeletionOutboxPort.Method;
import com.fivucsas.identity.repository.BiometricDeletionOutboxRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("BiometricDeletionOutboxAdapter")
class BiometricDeletionOutboxAdapterTest {

    @Mock private BiometricDeletionOutboxRepository repository;
    @InjectMocks private BiometricDeletionOutboxAdapter adapter;

    @Test
    @DisplayName("enqueue inserts idempotently and reports whether a row was created")
    void enqueue_isIdempotent() {
        UUID userId = UUID.randomUUID();
        when(repository.insertIfAbsent(any(), eq(userId), eq("FACE"))).thenReturn(1, 0);

        assertThat(adapter.enqueue(userId, Method.FACE)).isTrue();
        assertThat(adapter.enqueue(userId, Method.FACE)).isFalse();
    }

    @Test
    @DisplayName("markFailed truncates last_error to the column width")
    void markFailed_truncates() {
        UUID id = UUID.randomUUID();
        Instant next = Instant.now();

        adapter.markFailed(id, "x".repeat(5000), next);

        ArgumentCaptor<String> err = ArgumentCaptor.forClass(String.class);
        verify(repository).markFailed(eq(id), err.capture(), eq(next));
        assertThat(err.getValue()).hasSize(BiometricDeletionOutboxAdapter.MAX_ERROR_LENGTH);
    }
}
