package com.fivucsas.identity.infrastructure.multitenancy;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.hibernate.Filter;
import org.hibernate.Session;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Aspect that automatically enables the Hibernate tenant filter
 * and PostgreSQL RLS session variable for all repository method calls.
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class TenantFilterAspect {

    private final EntityManager entityManager;

    /**
     * Before any repository method execution, enable the tenant filter
     * and set the RLS session variable if a tenant context is available.
     */
    @Before("execution(* com.fivucsas.identity.repository.*.*(..))")
    public void enableTenantFilter(JoinPoint joinPoint) {
        if (TenantContext.hasTenant()) {
            UUID tenantId = TenantContext.requireCurrentTenant();
            Session session = entityManager.unwrap(Session.class);
            Filter filter = session.enableFilter("tenantFilter");
            filter.setParameter("tenantId", tenantId);

            // Set PostgreSQL session variable for Row-Level Security (RLS).
            // SET LOCAL scopes the variable to the current transaction.
            session.doWork(connection -> {
                try (var stmt = connection.createStatement()) {
                    stmt.execute("SET LOCAL app.current_tenant_id = '"
                            + tenantId.toString() + "'");
                }
            });

            log.trace("Tenant filter + RLS enabled for tenant: {} on method: {}",
                    tenantId,
                    joinPoint.getSignature().getName());
        }
    }
}
