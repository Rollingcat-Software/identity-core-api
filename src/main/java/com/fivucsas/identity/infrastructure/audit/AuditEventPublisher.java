package com.fivucsas.identity.infrastructure.audit;

import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.repository.AuditLogRepository;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
 *
 * <h3>Failure observability (P1 hygiene 2026-05-07)</h3>
 * <p>Audit-write failures (RLS rejection, missing partition, constraint
 * violations, lock timeouts on the JDBC connection) used to disappear into
 * a single {@code log.error(...)} line with no metric — so silent audit drops
 * were invisible to alerting. We now increment a Micrometer counter
 * {@code audit.publish.failure} tagged by exception type on every swallowed
 * exception. The Prometheus scrape exposes this counter under
 * {@code audit_publish_failure_total} and an alert rule can fire on any
 * non-zero rate. The exception itself is still logged at ERROR with full
 * stack trace so the cause is recoverable from logs.</p>
 */
@Component
@Slf4j
public class AuditEventPublisher {

    private static final String FAILURE_COUNTER = "audit.publish.failure";
    private static final String EXCEPTION_TAG = "exception";

    private final AuditLogRepository auditLogRepository;
    private final MeterRegistry meterRegistry;

    /**
     * Two-arg constructor. {@link MeterRegistry} is optional so this component
     * remains constructible from unit tests that do not boot a Spring Boot
     * context (and hence do not provide a registry). Production wiring always
     * gets the auto-configured Prometheus-backed registry.
     */
    @Autowired
    public AuditEventPublisher(AuditLogRepository auditLogRepository,
                               MeterRegistry meterRegistry) {
        this.auditLogRepository = auditLogRepository;
        this.meterRegistry = meterRegistry;
    }

    /**
     * Convenience constructor for unit tests that do not need a metrics
     * registry. Failure-counter increments are no-ops in this mode.
     */
    public AuditEventPublisher(AuditLogRepository auditLogRepository) {
        this(auditLogRepository, null);
    }

    /**
     * Persists an audit log row asynchronously. Failures are swallowed and
     * logged so audit-write problems can never poison a business operation,
     * but each swallowed failure increments the {@code audit.publish.failure}
     * Micrometer counter (tagged by exception type) so silent drops surface
     * in observability.
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
            recordFailure(e, auditLog);
            log.error("Failed to save audit log: action={} resourceType={} error={}",
                    auditLog.getAction(), auditLog.getResourceType(), e.getMessage(), e);
        } finally {
            if (previous != null) {
                TenantContext.setCurrentTenant(previous);
            } else {
                TenantContext.clear();
            }
        }
    }

    /**
     * Increments {@code audit.publish.failure} tagged by exception type. A
     * null registry (test-only constructor) is a no-op.
     */
    private void recordFailure(Exception e, AuditLog auditLog) {
        if (meterRegistry == null) {
            return;
        }
        try {
            meterRegistry.counter(
                    FAILURE_COUNTER,
                    EXCEPTION_TAG, e.getClass().getSimpleName()
            ).increment();
        } catch (RuntimeException meterFailure) {
            // A metrics failure must never poison the audit path. Log at WARN
            // (not ERROR) so the original ERROR entry above remains the
            // primary signal in dashboards.
            log.warn("Failed to increment {} counter: {}",
                    FAILURE_COUNTER, meterFailure.getMessage());
        }
    }
}
