package com.fivucsas.identity.infrastructure.audit;

import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.repository.AuditLogRepository;
import com.fivucsas.identity.security.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Parameter;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Aspect that automatically logs audit events for methods annotated with @Audited.
 * Runs asynchronously to avoid impacting application performance.
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditLoggingAspect {

    private final AuditLogRepository auditLogRepository;

    @AfterReturning(pointcut = "@annotation(audited)", returning = "result")
    public void logSuccess(JoinPoint joinPoint, Audited audited, Object result) {
        logAuditEvent(joinPoint, audited, true, null);
    }

    @AfterThrowing(pointcut = "@annotation(audited)", throwing = "ex")
    public void logFailure(JoinPoint joinPoint, Audited audited, Exception ex) {
        logAuditEvent(joinPoint, audited, false, ex.getMessage());
    }

    @Async
    private void logAuditEvent(JoinPoint joinPoint, Audited audited, boolean success, String errorMessage) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            CustomUserDetails user = auth != null && auth.getPrincipal() instanceof CustomUserDetails
                    ? (CustomUserDetails) auth.getPrincipal()
                    : null;

            HttpServletRequest request = getHttpRequest();

            AuditLog auditLog = AuditLog.builder()
                    .tenantId(TenantContext.getCurrentTenant())
                    .userId(user != null ? user.getUserId() : null)
                    .action(audited.action().name())
                    .resourceType(audited.resourceType())
                    .resourceId(extractResourceId(joinPoint, audited))
                    .httpMethod(request != null ? request.getMethod() : null)
                    .endpoint(request != null ? request.getRequestURI() : null)
                    .ipAddress(getClientIp(request))
                    .userAgentV2(request != null ? request.getHeader("User-Agent") : null)
                    .success(success)
                    .errorMessage(errorMessage)
                    .metadata(extractMetadata(joinPoint, audited))
                    .build();

            auditLogRepository.save(auditLog);

            log.debug("Audit log saved: {} for user {} on {}",
                    audited.action(), user != null ? user.getUserId() : "anonymous", audited.resourceType());
        } catch (Exception e) {
            // Don't let audit logging failures affect business operations
            log.error("Failed to save audit log: {}", e.getMessage(), e);
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
                        metadata.put(paramName, args[i]);
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
