package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.UserDataExportUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.exception.RateLimitExceededException;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * GDPR Art. 20 / KVKK data-portability endpoint.
 *
 * <p>Returns a user's personal data as a downloadable JSON file. A user may export only their
 * own data; a tenant admin may export any user in their tenant; ROOT may export across
 * tenants. Rate-limited to 1 export per hour per user to protect the backend from accidental
 * or malicious bulk scrapes.</p>
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Data Export", description = "GDPR Art. 20 / KVKK data portability")
public class UserDataExportController {

    private final UserDataExportUseCase userDataExportUseCase;
    private final RbacAuthorizationService rbacService;
    private final RateLimitService rateLimitService;
    private final AuditLogPort auditLogPort;

    @GetMapping("/{id}/export")
    @Operation(summary = "Export a user's personal data (GDPR Art. 20 / KVKK)",
               description = "Returns JSON bundle of personal data the controller holds about the user. "
                   + "Authorization: self-export, tenant admin for tenant members, or ROOT.")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> exportUserData(
            @PathVariable("id") UUID userId,
            HttpServletRequest request) {
        log.info("GET /api/v1/users/{}/export - GDPR data export requested", userId);

        User caller = rbacService.getCurrentUser()
            .orElseThrow(() -> new UnauthorizedException("Authentication required"));

        // Rate-limit BEFORE authorization so a denied user still consumes a token and can't
        // enumerate other user ids via timing. 1 export / hour / caller.
        if (!rateLimitService.allowDataExport(caller.getId().toString())) {
            long retryAfter = rateLimitService.getSecondsUntilRefill(
                caller.getId().toString(), RateLimitService.RateLimitType.EXPORT);
            throw new RateLimitExceededException(
                "Data export rate limit exceeded. Try again later.", retryAfter);
        }

        authorize(caller, userId);

        Map<String, Object> bundle;
        try {
            bundle = userDataExportUseCase.exportUserData(userId);
        } catch (UserNotFoundException e) {
            // Re-throw; GlobalExceptionHandler maps to 404
            throw e;
        }

        String clientIp = getClientIp(request);
        auditLogPort.logSecurityEvent(
            caller.getId().toString(),
            "USER_DATA_EXPORTED",
            clientIp,
            String.format("targetUserId=%s, callerEmail=%s", userId, caller.getEmail()));

        String filename = String.format("fivucsas-export-%s-%s.json",
            userId, Instant.now().toString().replace(":", "-"));
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
            .body(bundle);
    }

    /**
     * Authorizes the caller for the target user.
     * Rules:
     * <ul>
     *   <li>ROOT may export any user (cross-tenant).</li>
     *   <li>Tenant admins may export users in their tenant.</li>
     *   <li>Any authenticated user may export their own data.</li>
     * </ul>
     */
    private void authorize(User caller, UUID targetUserId) {
        if (caller.getId().equals(targetUserId)) {
            return;  // self-export
        }
        if (caller.isRoot()) {
            return;  // ROOT crosses tenants
        }
        if (caller.isTenantAdmin()) {
            // Admin must be in same tenant as target. canManage() delegates to UserType hierarchy
            // but requires a target User; a minimal tenant check is safer and avoids N+1.
            // The service will still 404 if user doesn't exist.
            if (!rbacService.canManageUser(targetUserId)) {
                throw new UnauthorizedException(
                    "Cannot export user outside your tenant");
            }
            return;
        }
        throw new UnauthorizedException(
            "You may only export your own data");
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
