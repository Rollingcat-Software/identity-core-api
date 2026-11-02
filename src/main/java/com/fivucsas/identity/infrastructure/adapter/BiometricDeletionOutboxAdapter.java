package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.BiometricDeletionOutboxPort;
import com.fivucsas.identity.entity.BiometricDeletionOutboxEntry;
import com.fivucsas.identity.repository.BiometricDeletionOutboxRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** JPA adapter for {@link BiometricDeletionOutboxPort}. */
@Repository
@RequiredArgsConstructor
public class BiometricDeletionOutboxAdapter implements BiometricDeletionOutboxPort {

    /** {@code last_error} column width (V87). */
    static final int MAX_ERROR_LENGTH = 1000;

    private final BiometricDeletionOutboxRepository repository;

    @Override
    public boolean enqueue(UUID userId, Method method) {
        return repository.insertIfAbsent(UUID.randomUUID(), userId, method.name()) > 0;
    }

    @Override
    public List<PendingDeletion> findDue(Instant now, int maxAttempts, int limit) {
        return repository.findDue(now, maxAttempts, PageRequest.of(0, limit)).stream()
                .map(BiometricDeletionOutboxAdapter::toPending)
                .toList();
    }

    @Override
    public void markCompleted(UUID id, Instant completedAt) {
        repository.markCompleted(id, completedAt);
    }

    @Override
    public void markFailed(UUID id, String lastError, Instant nextAttemptAt) {
        String error = lastError;
        if (error != null && error.length() > MAX_ERROR_LENGTH) {
            error = error.substring(0, MAX_ERROR_LENGTH);
        }
        repository.markFailed(id, error, nextAttemptAt);
    }

    private static PendingDeletion toPending(BiometricDeletionOutboxEntry e) {
        return new PendingDeletion(e.getId(), e.getUserId(), e.getTenantId(),
                Method.valueOf(e.getMethod()), e.getAttempts());
    }
}
