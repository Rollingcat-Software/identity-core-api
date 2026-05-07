package com.fivucsas.identity.infrastructure.audit;

import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.repository.AuditLogRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link AuditEventPublisher} focused on cross-thread tenant
 * context propagation.
 *
 * <p>Background: {@code @Async} dispatches audit writes onto a worker thread
 * pool. Without explicit propagation, {@link TenantContext} (a
 * {@link ThreadLocal}) is empty on the worker, so
 * {@link com.fivucsas.identity.infrastructure.multitenancy.TenantHibernateAspect}
 * cannot set the PostgreSQL {@code app.current_tenant_id} session variable
 * required by Row-Level Security — the INSERT is rejected and the audit row
 * is silently dropped.</p>
 *
 * <p>These tests pin the contract that {@link AuditEventPublisher#publish}
 * restores the tenant id on whichever thread it runs on, before delegating
 * to {@link AuditLogRepository#save}, and clears it afterwards so the worker
 * thread does not leak tenant state to its next task.</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuditEventPublisher — RLS-safe tenant context propagation")
class AuditEventPublisherTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    private MeterRegistry meterRegistry;
    private AuditEventPublisher publisher;

    @BeforeEach
    void setUp() {
        TenantContext.clear();
        meterRegistry = new SimpleMeterRegistry();
        publisher = new AuditEventPublisher(auditLogRepository, meterRegistry);
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    @DisplayName("On a fresh worker thread (empty TenantContext), publish() restores tenant before save")
    void restoresTenantOnWorkerThread() throws Exception {
        UUID tenantId = UUID.randomUUID();
        UUID[] tenantSeenBySave = new UUID[1];
        Thread[] saveThread = new Thread[1];

        when(auditLogRepository.save(any(AuditLog.class))).thenAnswer((InvocationOnMock inv) -> {
            // Capture exactly what TenantHibernateAspect would observe at the
            // moment of the JPA save call.
            tenantSeenBySave[0] = TenantContext.getCurrentTenant();
            saveThread[0] = Thread.currentThread();
            return inv.getArgument(0);
        });

        AuditLog log = AuditLog.builder()
                .action("USER_LOGIN").resourceType("USER").success(true).build();

        // Run on a separate thread to simulate Spring's @Async dispatch.
        // The Mockito-instantiated publisher has no proxy, so we manually
        // invoke it from a worker thread to reproduce the RLS dropout.
        Thread mainThread = Thread.currentThread();
        CompletableFuture
                .runAsync(() -> publisher.publish(log, tenantId),
                        Executors.newSingleThreadExecutor())
                .get();

        assertThat(saveThread[0])
                .as("save() must execute on a different thread to prove async semantics")
                .isNotEqualTo(mainThread);
        assertThat(tenantSeenBySave[0])
                .as("TenantContext must hold the captured tenant on the worker thread")
                .isEqualTo(tenantId);
        verify(auditLogRepository).save(any(AuditLog.class));
    }

    @Test
    @DisplayName("Worker thread has TenantContext cleared after publish() completes")
    void clearsTenantContextOnWorkerAfterSave() throws ExecutionException, InterruptedException {
        UUID tenantId = UUID.randomUUID();
        UUID[] tenantAfter = new UUID[1];

        AuditLog log = AuditLog.builder()
                .action("USER_LOGIN").resourceType("USER").success(true).build();

        CompletableFuture
                .runAsync(() -> {
                    publisher.publish(log, tenantId);
                    tenantAfter[0] = TenantContext.getCurrentTenant();
                }, Executors.newSingleThreadExecutor())
                .get();

        assertThat(tenantAfter[0])
                .as("Worker thread must not leak tenant state to subsequent tasks")
                .isNull();
    }

    @Test
    @DisplayName("Null tenantId is tolerated (cross-tenant / system events)")
    void nullTenantIdLeavesContextEmpty() {
        UUID[] tenantSeenBySave = new UUID[]{UUID.randomUUID()};

        when(auditLogRepository.save(any(AuditLog.class))).thenAnswer((InvocationOnMock inv) -> {
            tenantSeenBySave[0] = TenantContext.getCurrentTenant();
            return inv.getArgument(0);
        });

        AuditLog log = AuditLog.builder()
                .action("FAILED_LOGIN_ATTEMPT").resourceType("USER").success(false).build();

        publisher.publish(log, null);

        assertThat(tenantSeenBySave[0])
                .as("With null tenantId, no tenant context should be installed")
                .isNull();
    }

    @Test
    @DisplayName("Repository failure is swallowed — never poisons the calling business operation")
    void repositoryFailureIsSwallowed() {
        when(auditLogRepository.save(any(AuditLog.class)))
                .thenThrow(new RuntimeException("RLS rejected insert"));

        AuditLog log = AuditLog.builder()
                .action("USER_LOGIN").resourceType("USER").success(true).build();

        // Must not throw.
        publisher.publish(log, UUID.randomUUID());
    }

    @Test
    @DisplayName("Repository failure increments audit.publish.failure counter tagged by exception type (P1)")
    void repositoryFailureIncrementsCounter() {
        when(auditLogRepository.save(any(AuditLog.class)))
                .thenThrow(new IllegalStateException("RLS rejected insert"));

        AuditLog log = AuditLog.builder()
                .action("USER_LOGIN").resourceType("USER").success(true).build();

        publisher.publish(log, UUID.randomUUID());

        double count = meterRegistry.counter(
                "audit.publish.failure",
                "exception", "IllegalStateException"
        ).count();
        assertThat(count)
                .as("audit.publish.failure{exception=IllegalStateException} must increment when save throws — observability gate for silent audit drops")
                .isEqualTo(1.0);
    }

    @Test
    @DisplayName("Counter is tagged by exception class — different failures produce distinct series")
    void counterTagsAreDistinctPerExceptionType() {
        when(auditLogRepository.save(any(AuditLog.class)))
                .thenThrow(new IllegalArgumentException("bad payload"))
                .thenThrow(new IllegalStateException("rls"))
                .thenThrow(new IllegalStateException("rls again"));

        AuditLog log = AuditLog.builder()
                .action("USER_LOGIN").resourceType("USER").success(true).build();

        publisher.publish(log, UUID.randomUUID());
        publisher.publish(log, UUID.randomUUID());
        publisher.publish(log, UUID.randomUUID());

        assertThat(meterRegistry.counter("audit.publish.failure",
                "exception", "IllegalArgumentException").count())
                .isEqualTo(1.0);
        assertThat(meterRegistry.counter("audit.publish.failure",
                "exception", "IllegalStateException").count())
                .isEqualTo(2.0);
    }

    @Test
    @DisplayName("Successful publish does NOT increment the failure counter")
    void successfulPublishDoesNotIncrementCounter() {
        AuditLog log = AuditLog.builder()
                .action("USER_LOGIN").resourceType("USER").success(true).build();

        publisher.publish(log, UUID.randomUUID());

        // No tag-specific counter created → search returns nothing.
        assertThat(meterRegistry.find("audit.publish.failure").counters())
                .as("a successful publish must leave the failure counter untouched")
                .isEmpty();
    }

    @Test
    @DisplayName("Test-only single-arg constructor tolerates absent MeterRegistry (counter increment is a no-op)")
    void singleArgConstructorTolerantOfMissingRegistry() {
        AuditEventPublisher noMetricsPublisher = new AuditEventPublisher(auditLogRepository);
        when(auditLogRepository.save(any(AuditLog.class)))
                .thenThrow(new RuntimeException("boom"));

        AuditLog log = AuditLog.builder()
                .action("USER_LOGIN").resourceType("USER").success(true).build();

        // Must not throw — the recordFailure path must short-circuit when
        // meterRegistry is null.
        noMetricsPublisher.publish(log, UUID.randomUUID());
    }

    @Test
    @DisplayName("Pre-existing TenantContext on caller thread is restored after publish()")
    void restoresPreviousTenantOnCallerThread() {
        UUID outerTenant = UUID.randomUUID();
        UUID innerTenant = UUID.randomUUID();
        TenantContext.setCurrentTenant(outerTenant);

        AuditLog log = AuditLog.builder()
                .action("USER_LOGIN").resourceType("USER").success(true).build();

        // When the publisher runs on the same thread (e.g. test or
        // CallerRunsPolicy back-pressure), the caller's tenant must be
        // restored after publish() completes.
        publisher.publish(log, innerTenant);

        assertThat(TenantContext.getCurrentTenant())
                .as("Outer/caller tenant must be restored after publish")
                .isEqualTo(outerTenant);
    }
}
