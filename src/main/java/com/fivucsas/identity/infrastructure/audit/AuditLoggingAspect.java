package com.fivucsas.identity.infrastructure.audit;

import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.security.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Parameter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Aspect that automatically logs audit events for methods annotated with @Audited.
 * Persistence is delegated to {@link AuditEventPublisher} which runs asynchronously
 * via Spring's @Async proxy — keeping dispatch out of this class is required because
 * @Async on a private (or same-class-internal) method is bypassed by the AOP proxy.
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditLoggingAspect {

    private final AuditEventPublisher auditEventPublisher;

    @AfterReturning(pointcut = "@annotation(audited)", returning = "result")
    public void logSuccess(JoinPoint joinPoint, Audited audited, Object result) {
        emit(joinPoint, audited, true, null);
    }

    @AfterThrowing(pointcut = "@annotation(audited)", throwing = "ex")
    public void logFailure(JoinPoint joinPoint, Audited audited, Exception ex) {
        emit(joinPoint, audited, false, ex.getMessage());
    }

    private void emit(JoinPoint joinPoint, Audited audited, boolean success, String errorMessage) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            CustomUserDetails user = auth != null && auth.getPrincipal() instanceof CustomUserDetails
                    ? (CustomUserDetails) auth.getPrincipal()
                    : null;

            HttpServletRequest request = getHttpRequest();

            // Capture the tenant id on the calling (request-bound) thread.
            // The async worker thread has its own empty ThreadLocal, so the
            // value must be passed explicitly to the publisher and re-installed
            // on the worker before the JPA save runs — otherwise RLS rejects
            // the INSERT and the audit row is silently dropped.
            UUID tenantId = TenantContext.getCurrentTenant();

            AuditLog auditLog = AuditLog.builder()
                    .tenantId(tenantId)
                    .userId(user != null ? user.getUserId() : null)
                    // §P2-1 defense-in-depth: action is sourced from an enum
                    // and resourceType from an annotation literal today, but
                    // escape both consistently so the contract matches
                    // AuditLogAdapter's direct-write path. endpoint also
                    // escapes — request URIs include path variables like
                    // /api/v1/users/{id} where the bound id is caller-supplied
                    // and could carry HTML special chars in degenerate cases.
                    .action(AuditEscape.escape(audited.action().name()))
                    .resourceType(AuditEscape.escape(audited.resourceType()))
                    .resourceId(extractResourceId(joinPoint, audited))
                    .httpMethod(request != null ? request.getMethod() : null)
                    .endpoint(request != null && request.getRequestURI() != null
                            ? AuditEscape.escape(request.getRequestURI())
                            : null)
                    .ipAddress(getClientIp(request))
                    // userAgentV2 holds raw browser-supplied User-Agent header
                    // and is the value preferred by AuditLog.getEffectiveUserAgent().
                    // Escape on the way in so a downstream renderer that drops
                    // its escaping cannot produce executable HTML from an
                    // attacker-controlled UA string. Mirrors AuditLogAdapter's
                    // userAgent escaping for the legacy column.
                    .userAgentV2(request != null
                            ? AuditEscape.escape(request.getHeader("User-Agent"))
                            : null)
                    .success(success)
                    .errorMessage(AuditEscape.escape(errorMessage))
                    .metadata(extractMetadata(joinPoint, audited))
                    .build();

            auditEventPublisher.publish(auditLog, tenantId);
        } catch (Exception e) {
            // Don't let audit logging failures affect business operations.
            log.error("Failed to assemble audit log: {}", e.getMessage(), e);
        }
    }

    private UUID extractResourceId(JoinPoint joinPoint, Audited audited) {
        try {
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            Parameter[] parameters = signature.getMethod().getParameters();
            Object[] args = joinPoint.getArgs();

            for (int i = 0; i < parameters.length; i++) {
                if (parameters[i].getName().equals(audited.resourceIdParam())) {
                    Object value = args[i];
                    if (value instanceof UUID) {
                        return (UUID) value;
                    } else if (value instanceof String) {
                        return UUID.fromString((String) value);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to extract resource ID: {}", e.getMessage());
        }
        return null;
    }

    private Map<String, Object> extractMetadata(JoinPoint joinPoint, Audited audited) {
        Map<String, Object> metadata = new HashMap<>();

        try {
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            Parameter[] parameters = signature.getMethod().getParameters();
            Object[] args = joinPoint.getArgs();

            for (String paramName : audited.includeParams()) {
                for (int i = 0; i < parameters.length; i++) {
                    if (parameters[i].getName().equals(paramName)) {
                        // Defense-in-depth: if a UI ever renders metadata without
                        // escaping, a String parameter (e.g., displayName) could
                        // carry <script>. Escape strings here; pass other types
                        // through unchanged.
                        metadata.put(paramName, AuditEscape.escapeIfString(args[i]));
                        break;
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to extract metadata: {}", e.getMessage());
        }

        return metadata;
    }

    private String getClientIp(HttpServletRequest request) {
        if (request == null) return null;

        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private HttpServletRequest getHttpRequest() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attributes != null ? attributes.getRequest() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
