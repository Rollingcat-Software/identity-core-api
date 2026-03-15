package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.AuthSessionStep;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for AuthSessionStep persistence operations.
 */
public interface AuthSessionStepRepositoryPort {

    List<AuthSessionStep> findAllBySessionId(UUID sessionId);

    Optional<AuthSessionStep> findBySessionIdAndAuthFlowStepId(UUID sessionId, UUID flowStepId);

    Optional<AuthSessionStep> findByDelegationToken(String token);

    AuthSessionStep save(AuthSessionStep step);
}
