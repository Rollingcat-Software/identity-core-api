package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.CompleteAuthStepCommand;
import com.fivucsas.identity.application.dto.command.StartAuthSessionCommand;
import com.fivucsas.identity.application.dto.response.AuthSessionResponse;
import com.fivucsas.identity.application.dto.response.StepResultResponse;

import java.util.UUID;

public interface ExecuteAuthSessionUseCase {
    AuthSessionResponse startSession(StartAuthSessionCommand command);
    AuthSessionResponse getSessionStatus(UUID sessionId);
    StepResultResponse completeStep(UUID sessionId, int stepOrder, CompleteAuthStepCommand command);
    StepResultResponse skipStep(UUID sessionId, int stepOrder);
    void cancelSession(UUID sessionId);

    /**
     * Cancel a session if it exists. Returns {@code true} when a row was found
     * (and either cancelled now or was already in a terminal state); {@code false}
     * when no session matched the id. Idempotent — safe to retry. Post-audit
     * 2026-04-24 login edge case #3.
     */
    boolean tryCancelSession(UUID sessionId);
}
