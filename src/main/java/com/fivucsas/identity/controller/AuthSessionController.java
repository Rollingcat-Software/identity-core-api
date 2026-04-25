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
import com.fivucsas.identity.application.service.AuthSessionQueryService;
import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.security.TenantScopeResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
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
    private final AuthSessionQueryService authSessionQueryService;
    private final TenantScopeResolver tenantScopeResolver;

    // --- /api/v1/auth/sessions endpoints (original AuthSessionController) ---

    /**
     * Admin list — paginated, tenant-scoped enumeration of auth sessions.
     *
     * <p>TENANT_ADMIN sees only their own tenant's sessions; SUPER_ADMIN must
     * pass {@code tenantId} explicitly (we do not dump every tenant's
     * sessions in one call). Callers without a resolvable tenant get an
     * empty page (fail-closed sentinel).</p>
     *
     * <p>Query params:
     * <ul>
     *   <li>{@code tenantId} — required for SUPER_ADMIN; ignored (overridden
     *       by caller scope) for tenant-scoped users.</li>
     *   <li>{@code status} — optional comma-separated list (e.g.
     *       {@code CREATED,IN_PROGRESS}).</li>
     *   <li>{@code userId} — optional, restrict to a single user.</li>
     *   <li>{@code page}, {@code size} — standard pagination.</li>
     * </ul></p>
     */
    @GetMapping
    @Operation(
        summary = "List auth sessions (admin)",
        description = "Tenant-scoped paginated list of authentication sessions. " +
                      "TENANT_ADMIN/audit:read; SUPER_ADMIN must pass tenantId."
    )
    @PreAuthorize("@rbac.isTenantAdmin() or hasAuthority('audit:read')")
    public ResponseEntity<Map<String, Object>> listSessions(
            @RequestParam(required = false) UUID tenantId,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) UUID userId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        UUID callerScope = tenantScopeResolver.currentScope();
        UUID effectiveTenantId;

        if (callerScope == null) {
            // SUPER_ADMIN — must supply tenantId explicitly.
            if (tenantId == null) {
                throw new IllegalArgumentException("'tenantId' query parameter is required for SUPER_ADMIN.");
            }
            effectiveTenantId = tenantId;
        } else if (TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE.equals(callerScope)) {
            // Caller without resolvable tenant — fail closed (empty page).
            return ResponseEntity.ok(Map.of(
                    "content", List.of(),
                    "totalElements", 0L,
                    "totalPages", 0,
                    "page", 0,
                    "size", size
            ));
        } else {
            // Tenant-scoped caller: ignore any tenantId that isn't theirs.
            effectiveTenantId = callerScope;
        }

        List<AuthSessionStatus> statusFilter = parseStatuses(status);

        log.info("GET /api/v1/auth/sessions - tenantId={}, status={}, userId={}, page={}, size={}",
                effectiveTenantId, statusFilter, userId, page, size);

        Map<String, Object> body = authSessionQueryService.listForTenant(
                effectiveTenantId, statusFilter, userId, page, size);
        return ResponseEntity.ok(body);
    }

    private List<AuthSessionStatus> parseStatuses(String csv) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> {
                    try {
                        return AuthSessionStatus.valueOf(s.toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        throw new IllegalArgumentException(
                                "Unknown auth session status: '" + s + "'. " +
                                "Valid values: CREATED, IN_PROGRESS, COMPLETED, FAILED, EXPIRED, CANCELLED.");
                    }
                })
                .toList();
    }

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
