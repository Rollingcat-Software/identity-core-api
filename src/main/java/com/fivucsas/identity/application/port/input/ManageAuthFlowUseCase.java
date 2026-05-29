package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.CreateAuthFlowCommand;
import com.fivucsas.identity.application.dto.command.UpdateAuthFlowCommand;
import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.dto.response.AuthFlowDefaultImpactResponse;
import com.fivucsas.identity.domain.model.auth.OperationType;

import java.util.List;
import java.util.UUID;

public interface ManageAuthFlowUseCase {
    List<AuthFlowResponse> listFlows(UUID tenantId, OperationType operationType);
    AuthFlowResponse getFlow(UUID tenantId, UUID flowId);
    AuthFlowResponse createFlow(UUID tenantId, CreateAuthFlowCommand command);
    AuthFlowResponse updateFlow(UUID tenantId, UUID flowId, UpdateAuthFlowCommand command);
    void deleteFlow(UUID tenantId, UUID flowId);

    /**
     * Advisory: how many tenant users would be unable to complete {@code flowId}
     * if it became the default for its operation type (lockout-prevention).
     */
    AuthFlowDefaultImpactResponse computeDefaultImpact(UUID tenantId, UUID flowId);
}
