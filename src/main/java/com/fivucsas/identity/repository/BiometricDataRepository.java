package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.BiometricData;
import com.fivucsas.identity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * JPA Repository for BiometricData entity.
 *
 * Implements domain repository contract + JPA features.
 * Following Dependency Inversion Principle.
 */
@Repository
public interface BiometricDataRepository extends
        JpaRepository<BiometricData, UUID>,
        com.fivucsas.identity.domain.repository.BiometricDataRepository {

    Optional<BiometricData> findByUser(User user);

    Optional<BiometricData> findByUserId(UUID userId);

    void deleteByUser(User user);

    @Override
    default void deleteRecord(BiometricData data) {
        delete(data);
    }
}
