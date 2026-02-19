package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.AuthBiometricDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthBiometricDeviceRepository extends JpaRepository<AuthBiometricDevice, UUID> {
    Optional<AuthBiometricDevice> findByUserIdAndKeyIdAndIsActiveTrue(UUID userId, String keyId);
}
