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
 * Aspect to enable Hibernate tenant filter for repository operations.
 *
 * Automatically enables the tenant filter before any repository method
 * when a tenant context is available.
 *
 * Following principles:
 * - Single Responsibility: Only manages filter activation
 * - Open/Closed: Can be extended for different filter types
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class TenantHibernateAspect {

    private final EntityManager entityManager;

    /**
     * Enables tenant filter before repository operations.
     */
    @Before("execution(* com.fivucsas.identity.repository..*(..))")
    public void enableTenantFilter() {
        UUID tenantId = TenantContext.getCurrentTenant();

        if (tenantId != null) {
            Session session = entityManager.unwrap(Session.class);

            if (!session.getEnabledFilter("tenantFilter") != null) {
                session.enableFilter("tenantFilter")
                       .setParameter("tenantId", tenantId);
                log.trace("Tenant filter enabled for tenant: {}", tenantId);
            }
        }
    }
}
