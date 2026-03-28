package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.CreateVerificationSessionCommand;
import com.fivucsas.identity.application.dto.command.ReviewVerificationStepCommand;
import com.fivucsas.identity.application.dto.command.SubmitVerificationStepCommand;
import com.fivucsas.identity.application.dto.response.IndustryTemplateResponse;
import com.fivucsas.identity.application.dto.response.VerificationSessionResponse;
import com.fivucsas.identity.application.dto.response.VerificationStatusResponse;
import com.fivucsas.identity.application.dto.response.VerificationStepResultResponse;
import com.fivucsas.identity.application.service.ManageVerificationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/verification")
@RequiredArgsConstructor
public class VerificationController {

    private final ManageVerificationService verificationService;

    @PostMapping("/sessions")
    public ResponseEntity<VerificationSessionResponse> createSession(
            @Valid @RequestBody CreateVerificationSessionCommand command) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(verificationService.createSession(command.userId(), command.tenantId(), command.flowId()));
    }

    @PostMapping("/sessions/{id}/steps/{stepNumber}")
    public ResponseEntity<VerificationStepResultResponse> submitStepResult(
            @PathVariable UUID id,
            @PathVariable int stepNumber,
            @Valid @RequestBody SubmitVerificationStepCommand command) {
        return ResponseEntity.ok(verificationService.submitStepResult(id, stepNumber, command));
    }

    @GetMapping("/sessions/{id}")
    public ResponseEntity<VerificationSessionResponse> getSession(@PathVariable UUID id) {
        return ResponseEntity.ok(verificationService.getSession(id));
    }

    @PostMapping("/sessions/{id}/complete")
    public ResponseEntity<VerificationSessionResponse> completeSession(@PathVariable UUID id) {
        return ResponseEntity.ok(verificationService.completeSession(id));
    }

    @GetMapping("/templates")
    public ResponseEntity<List<IndustryTemplateResponse>> getTemplates() {
        return ResponseEntity.ok(verificationService.getTemplates());
    }

    @GetMapping("/results/{userId}")
    public ResponseEntity<VerificationStatusResponse> getUserVerificationStatus(@PathVariable UUID userId) {
        return ResponseEntity.ok(verificationService.getUserVerificationStatus(userId));
    }

    @PostMapping("/sessions/{id}/steps/{stepNumber}/review")
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN', 'ROLE_TENANT_ADMIN')")
    public ResponseEntity<VerificationStepResultResponse> reviewStep(
            @PathVariable UUID id,
            @PathVariable int stepNumber,
            @Valid @RequestBody ReviewVerificationStepCommand command) {
        return ResponseEntity.ok(
                verificationService.reviewStep(id, stepNumber, command.approved(), command.notes()));
    }
}
