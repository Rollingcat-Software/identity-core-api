package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.RevokeAllSessionsCommand;
import com.fivucsas.identity.application.dto.command.RevokeSessionCommand;
import com.fivucsas.identity.application.dto.query.GetActiveSessionsQuery;
import com.fivucsas.identity.application.dto.response.SessionResponse;
import com.fivucsas.identity.application.port.input.GetActiveSessionsUseCase;
import com.fivucsas.identity.application.port.input.RevokeAllSessionsUseCase;
import com.fivucsas.identity.application.port.input.RevokeSessionUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST controller for session management endpoints.
 *
 * Following hexagonal architecture principles.
 *
 * Following principles:
 * - Adapter Pattern: REST adapter calling input ports
 * - Dependency Inversion: Depends on abstractions (use cases), not implementations
 * - Single Responsibility: Only handles HTTP concerns, delegates to use cases
 */
@RestController
@RequestMapping("/api/v1/sessions")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Session Management", description = "Session management endpoints")
public class SessionController {

    private final GetActiveSessionsUseCase getActiveSessionsUseCase;
    private final RevokeSessionUseCase revokeSessionUseCase;
    private final RevokeAllSessionsUseCase revokeAllSessionsUseCase;

    @GetMapping
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

    @DeleteMapping("/{sessionId}")
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

        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/all")
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

        return ResponseEntity.ok().build();
    }

    // Utility methods

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
