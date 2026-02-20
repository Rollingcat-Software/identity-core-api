package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.UserDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserDeviceRepository extends JpaRepository<UserDevice, UUID> {
    List<UserDevice> findAllByUserId(UUID userId);
    List<UserDevice> findAllByTenantId(UUID tenantId);
    Optional<UserDevice> findByUserIdAndDeviceFingerprint(UUID userId, String fingerprint);
    List<UserDevice> findAllByUserIdAndIsTrustedTrue(UUID userId);
}
