package com.fivucsas.identity.infrastructure.multitenancy;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.hibernate.Session;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Aspect to enable Hibernate tenant filter and PostgreSQL RLS
 * session variable for repository operations.
 *
 * Automatically enables the tenant filter and sets the RLS session
 * variable before any repository method when a tenant context is available.
 *
 * Following principles:
 * - Single Responsibility: Only manages tenant-scoped data access
 * - Open/Closed: Can be extended for different filter types
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class TenantHibernateAspect {

    private final EntityManager entityManager;

    /**
     * Enables tenant filter and sets RLS session variable before repository operations.
     */
    @Before("execution(* com.fivucsas.identity.repository..*(..))")
    public void enableTenantFilter() {
        UUID tenantId = TenantContext.getCurrentTenant();

        if (tenantId != null) {
            Session session = entityManager.unwrap(Session.class);

            if (session.getEnabledFilter("tenantFilter") == null) {
                session.enableFilter("tenantFilter")
                       .setParameter("tenantId", tenantId);
                log.trace("Tenant filter enabled for tenant: {}", tenantId);
            }

            // Set PostgreSQL session variable for Row-Level Security (RLS).
            // SET LOCAL scopes the variable to the current transaction,
            // so it is automatically cleared when the transaction ends.
            // Note: SET LOCAL does not support parameterized queries, but
            // tenantId is a UUID (safe: only hex digits and dashes).
            session.doWork(connection -> {
                try (var stmt = connection.createStatement()) {
                    stmt.execute("SET LOCAL app.current_tenant_id = '"
                            + tenantId.toString() + "'");
                }
            });
            log.trace("RLS session variable set for tenant: {}", tenantId);
        }
    }
}
