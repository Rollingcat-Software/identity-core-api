package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.PasswordHistory;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.UUID;

/**
 * Output port for password history persistence.
 *
 * Follows Dependency Inversion: application defines the contract,
 * infrastructure provides the implementation.
 */
public interface PasswordHistoryRepositoryPort {

    List<PasswordHistory> findRecentByUserId(UUID userId, Pageable pageable);

    PasswordHistory save(PasswordHistory passwordHistory);
}
