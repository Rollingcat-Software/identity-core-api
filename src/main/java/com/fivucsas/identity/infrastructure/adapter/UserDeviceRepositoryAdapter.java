package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.UserDeviceRepositoryPort;
import com.fivucsas.identity.entity.UserDevice;
import com.fivucsas.identity.repository.UserDeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class UserDeviceRepositoryAdapter implements UserDeviceRepositoryPort {

    private final UserDeviceRepository jpaRepository;

    @Override
    public Optional<UserDevice> findById(UUID id) {
        return jpaRepository.findById(id);
    }

    @Override
    public List<UserDevice> findAllByUserId(UUID userId) {
        return jpaRepository.findAllByUserId(userId);
    }

    @Override
    public List<UserDevice> findAllByTenantId(UUID tenantId) {
        return jpaRepository.findAllByTenantId(tenantId);
    }

    @Override
    public Optional<UserDevice> findByUserIdAndDeviceFingerprint(UUID userId, String fingerprint) {
        return jpaRepository.findByUserIdAndDeviceFingerprint(userId, fingerprint);
    }

    @Override
    public UserDevice save(UserDevice device) {
        return jpaRepository.save(device);
    }

    @Override
    public void delete(UserDevice device) {
        jpaRepository.delete(device);
    }
}
