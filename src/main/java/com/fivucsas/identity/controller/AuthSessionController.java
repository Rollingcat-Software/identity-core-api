package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.CompleteAuthStepCommand;
import com.fivucsas.identity.application.dto.command.RevokeAllSessionsCommand;
import com.fivucsas.identity.application.dto.command.RevokeSessionCommand;
import com.fivucsas.identity.application.dto.command.StartAuthSessionCommand;
import com.fivucsas.identity.application.dto.query.GetActiveSessionsQuery;
import com.fivucsas.identity.application.dto.response.AuthSessionResponse;
import com.fivucsas.identity.application.dto.response.SessionResponse;
import com.fivucsas.identity.application.dto.response.StepResultResponse;
import com.fivucsas.identity.application.port.input.ExecuteAuthSessionUseCase;
import com.fivucsas.identity.application.port.input.GetActiveSessionsUseCase;
import com.fivucsas.identity.application.port.input.RevokeAllSessionsUseCase;
import com.fivucsas.identity.application.port.input.RevokeSessionUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST controller for auth session and user session management.
 *
 * Merges: AuthSessionController (/api/v1/auth/sessions/*) + SessionController (/api/v1/auth/sessions/my/*)
 * User session management endpoints use the /my sub-path under the auth sessions base.
 */
@RestController
@RequestMapping("/api/v1/auth/sessions")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Session Management", description = "Auth session execution and user session management endpoints")
public class AuthSessionController {

    private final ExecuteAuthSessionUseCase executeAuthSessionUseCase;
    private final GetActiveSessionsUseCase getActiveSessionsUseCase;
    private final RevokeSessionUseCase revokeSessionUseCase;
    private final RevokeAllSessionsUseCase revokeAllSessionsUseCase;

    // --- /api/v1/auth/sessions endpoints (original AuthSessionController) ---

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

    // --- /api/v1/auth/sessions/my endpoints (user session management) ---

    @GetMapping("/my")
    @Operation(
        summary = "Get all active sessions",
        description = "Returns list of active sessions for the authenticated user",
        security = @SecurityRequirement(name = "bearer-jwt")
    )
    public ResponseEntity<List<SessionResponse>> getActiveSessions(
            Authentication authentication,
            @RequestParam(required = false) String currentTokenId) {
        log.info("Get active sessions request for user: {}", authentication.getName());

        GetActiveSessionsQuery query = GetActiveSessionsQuery.builder()
            .email(authentication.getName())
            .currentTokenId(currentTokenId)
            .build();

        List<SessionResponse> sessions = getActiveSessionsUseCase.execute(query);

        return ResponseEntity.ok(sessions);
    }

    @DeleteMapping("/my/{sessionId}")
    @Operation(
        summary = "Revoke a specific session",
        description = "Revokes a specific session by ID (logs out that device)",
        security = @SecurityRequirement(name = "bearer-jwt")
    )
    public ResponseEntity<Void> revokeSession(
            @PathVariable String sessionId,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Revoke session request: {} for user: {}", sessionId, authentication.getName());

        RevokeSessionCommand command = RevokeSessionCommand.builder()
            .email(authentication.getName())
            .sessionId(sessionId)
            .ipAddress(getClientIP(httpRequest))
            .build();

        revokeSessionUseCase.execute(command);

        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/my/all")
    @Operation(
        summary = "Revoke all other sessions",
        description = "Revokes all sessions except the current one (logout from all other devices)",
        security = @SecurityRequirement(name = "bearer-jwt")
    )
    public ResponseEntity<Void> revokeAllSessions(
            @RequestParam String currentTokenId,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Revoke all sessions request for user: {}", authentication.getName());

        RevokeAllSessionsCommand command = RevokeAllSessionsCommand.builder()
            .email(authentication.getName())
            .currentTokenId(currentTokenId)
            .ipAddress(getClientIP(httpRequest))
            .build();

        revokeAllSessionsUseCase.execute(command);

        return ResponseEntity.noContent().build();
    }

    // --- Private helpers ---

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
