package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.CompleteAuthStepCommand;
import com.fivucsas.identity.application.dto.command.StartAuthSessionCommand;
import com.fivucsas.identity.application.dto.response.AuthSessionResponse;
import com.fivucsas.identity.application.dto.response.StepResultResponse;
import com.fivucsas.identity.application.port.input.ExecuteAuthSessionUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth/sessions")
@RequiredArgsConstructor
public class AuthSessionController {

    private final ExecuteAuthSessionUseCase executeAuthSessionUseCase;

    @PostMapping
    public ResponseEntity<AuthSessionResponse> startSession(@RequestBody StartAuthSessionCommand command) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(executeAuthSessionUseCase.startSession(command));
    }

    @GetMapping("/{sessionId}")
    public ResponseEntity<AuthSessionResponse> getSession(@PathVariable UUID sessionId) {
        return ResponseEntity.ok(executeAuthSessionUseCase.getSessionStatus(sessionId));
    }

    @PostMapping("/{sessionId}/steps/{stepOrder}")
    public ResponseEntity<StepResultResponse> completeStep(
            @PathVariable UUID sessionId,
            @PathVariable int stepOrder,
            @RequestBody CompleteAuthStepCommand command) {
        return ResponseEntity.ok(executeAuthSessionUseCase.completeStep(sessionId, stepOrder, command));
    }

    @PostMapping("/{sessionId}/steps/{stepOrder}/skip")
    public ResponseEntity<StepResultResponse> skipStep(
            @PathVariable UUID sessionId,
            @PathVariable int stepOrder) {
        return ResponseEntity.ok(executeAuthSessionUseCase.skipStep(sessionId, stepOrder));
    }

    @PostMapping("/{sessionId}/cancel")
    public ResponseEntity<Void> cancelSession(@PathVariable UUID sessionId) {
        executeAuthSessionUseCase.cancelSession(sessionId);
        return ResponseEntity.noContent().build();
    }
}
