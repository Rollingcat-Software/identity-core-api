package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.BiometricData;
import com.fivucsas.identity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface BiometricDataRepository extends JpaRepository<BiometricData, UUID> {

    Optional<BiometricData> findByUser(User user);

    Optional<BiometricData> findByUserId(UUID userId);

    void deleteByUser(User user);
}
