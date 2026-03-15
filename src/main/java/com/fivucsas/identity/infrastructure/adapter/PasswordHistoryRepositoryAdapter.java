package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.PasswordHistoryRepositoryPort;
import com.fivucsas.identity.entity.PasswordHistory;
import com.fivucsas.identity.repository.PasswordHistoryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * Infrastructure adapter implementing PasswordHistoryRepositoryPort.
 * Delegates to the Spring Data JPA PasswordHistoryRepository.
 */
@Repository
@RequiredArgsConstructor
public class PasswordHistoryRepositoryAdapter implements PasswordHistoryRepositoryPort {

    private final PasswordHistoryRepository passwordHistoryRepository;

    @Override
    public List<PasswordHistory> findRecentByUserId(UUID userId, Pageable pageable) {
        return passwordHistoryRepository.findRecentByUserId(userId, pageable);
    }

    @Override
    public PasswordHistory save(PasswordHistory passwordHistory) {
        return passwordHistoryRepository.save(passwordHistory);
    }
}
