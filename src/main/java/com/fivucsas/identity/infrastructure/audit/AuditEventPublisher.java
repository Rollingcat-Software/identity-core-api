package com.fivucsas.identity.infrastructure.audit;

import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.util.UUID;

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
 *
 * <h3>RLS / tenant context propagation</h3>
 * <p>{@code AuditLogRepository} writes ride on {@code TenantHibernateAspect}
 * which reads {@link TenantContext} (a {@link ThreadLocal}) to issue
 * {@code SET LOCAL app.current_tenant_id = '...'}. PostgreSQL Row-Level
 * Security uses that variable to authorize the INSERT.</p>
 *
 * <p>{@code @Async} dispatches the call to a worker thread from
 * {@code AsyncConfig.taskExecutor()} where the calling thread's
 * {@link ThreadLocal} state is empty — so {@code TenantContext.getCurrentTenant()}
 * returns {@code null}, the RLS variable is never set, and the INSERT is
 * silently rejected (audit row dropped). To prevent that drop, the calling
 * thread captures the tenant id and we restore it on the worker thread inside
 * a try/finally so the worker is otherwise indistinguishable from a
 * request-bound thread for the brief window of the audit write.</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditEventPublisher {

    private final AuditLogRepository auditLogRepository;

    /**
     * Persists an audit log row asynchronously. Failures are swallowed and
     * logged so audit-write problems can never poison a business operation.
     *
     * <p>The {@code tenantId} parameter is the tenant id captured on the
     * calling thread (where {@code TenantContext} is populated by the request
     * filter). It is restored on the async worker thread before the
     * repository call so that {@link com.fivucsas.identity.infrastructure.multitenancy.TenantHibernateAspect}
     * can set the PostgreSQL {@code app.current_tenant_id} session variable
     * required by Row-Level Security. May be {@code null} for cross-tenant
     * (system / anonymous) events; in that case no tenant context is set on
     * the worker, mirroring synchronous behaviour.</p>
     */
    @Async
    public void publish(AuditLog auditLog, UUID tenantId) {
        UUID previous = TenantContext.getCurrentTenant();
        try {
            if (tenantId != null) {
                TenantContext.setCurrentTenant(tenantId);
            }
            auditLogRepository.save(auditLog);
            log.debug("Audit log saved: action={} resourceType={}",
                    auditLog.getAction(), auditLog.getResourceType());
        } catch (Exception e) {
            log.error("Failed to save audit log: {}", e.getMessage(), e);
        } finally {
            if (previous != null) {
                TenantContext.setCurrentTenant(previous);
            } else {
                TenantContext.clear();
            }
        }
    }
}
