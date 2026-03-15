package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthMethod;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for AuthMethod persistence operations.
 */
public interface AuthMethodRepositoryPort {

    List<AuthMethod> findAllByIsActiveTrue();

    Optional<AuthMethod> findByType(AuthMethodType type);

    Optional<AuthMethod> findById(UUID id);
}
