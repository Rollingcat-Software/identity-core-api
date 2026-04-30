package com.fivucsas.identity.infrastructure.audit;

import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Async dispatcher for audit events emitted by {@link AuditLoggingAspect}.
 *
 * <p>Lives in its own {@code @Component} so that {@link Async} actually goes
 * through Spring's CGLIB proxy. Spring's {@code @Async} works by returning a
 * proxy that intercepts method calls — when an annotated method is invoked
 * via {@code this.method(...)} from within the same class, the call bypasses
 * the proxy and runs synchronously. Aspects (woven by AspectJ) compound this:
 * the aspect class is itself a singleton bean and any internal call from one
 * advice method to another is direct. Extracting the persistence step into
 * this collaborator restores the proxy boundary and the {@code @Async}
 * annotation takes effect as documented.</p>
 *
 * <p>The save method is intentionally {@code public} — both for proxy access
 * and to make the contract explicit: callers must never block on the returned
 * value (this is fire-and-forget).</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditEventPublisher {

    private final AuditLogRepository auditLogRepository;

    /**
     * Persists an audit log row asynchronously. Failures are swallowed and
     * logged so audit-write problems can never poison a business operation.
     */
    @Async
    public void publish(AuditLog auditLog) {
        try {
            auditLogRepository.save(auditLog);
            log.debug("Audit log saved: action={} resourceType={}",
                    auditLog.getAction(), auditLog.getResourceType());
        } catch (Exception e) {
            log.error("Failed to save audit log: {}", e.getMessage(), e);
        }
    }
}
