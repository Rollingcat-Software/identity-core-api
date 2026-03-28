package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.UserSettings;

import java.util.Optional;
import java.util.UUID;

/**
 * Output port for UserSettings persistence operations.
 */
public interface UserSettingsRepositoryPort {

    Optional<UserSettings> findByUserId(UUID userId);

    <S extends UserSettings> S save(S settings);
}
