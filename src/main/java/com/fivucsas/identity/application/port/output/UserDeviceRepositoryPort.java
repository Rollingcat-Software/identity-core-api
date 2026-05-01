package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.UserDevice;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for UserDevice persistence operations.
 */
public interface UserDeviceRepositoryPort {

    Optional<UserDevice> findById(UUID id);

    List<UserDevice> findAllByUserId(UUID userId);

    List<UserDevice> findAllByTenantId(UUID tenantId);

    /** Platform-wide listing — used by SUPER_ADMIN admin UI. */
    List<UserDevice> findAll();

    Optional<UserDevice> findByUserIdAndDeviceFingerprint(UUID userId, String fingerprint);

    UserDevice save(UserDevice device);

    void delete(UserDevice device);
}
