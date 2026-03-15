package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.AuthFlowStep;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for AuthFlowStep persistence operations.
 */
public interface AuthFlowStepRepositoryPort {

    List<AuthFlowStep> findAllByAuthFlowIdOrderByStepOrderAsc(UUID flowId);

    Optional<AuthFlowStep> findByAuthFlowIdAndId(UUID flowId, UUID stepId);

    void deleteAllByAuthFlowId(UUID flowId);

    AuthFlowStep save(AuthFlowStep step);
}
