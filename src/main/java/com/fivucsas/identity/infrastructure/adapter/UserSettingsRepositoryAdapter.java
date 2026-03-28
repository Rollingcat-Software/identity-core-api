package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.UserSettingsRepositoryPort;
import com.fivucsas.identity.entity.UserSettings;
import com.fivucsas.identity.repository.UserSettingsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class UserSettingsRepositoryAdapter implements UserSettingsRepositoryPort {

    private final UserSettingsRepository jpaRepository;

    @Override
    public Optional<UserSettings> findByUserId(UUID userId) {
        return jpaRepository.findByUserId(userId);
    }

    @Override
    public <S extends UserSettings> S save(S settings) {
        return jpaRepository.save(settings);
    }
}
