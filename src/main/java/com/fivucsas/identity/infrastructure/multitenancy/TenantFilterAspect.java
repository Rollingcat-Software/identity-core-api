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

/**
 * Aspect that automatically enables the Hibernate tenant filter
 * for all repository method calls.
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class TenantFilterAspect {

    private final EntityManager entityManager;

    /**
     * Before any repository method execution, enable the tenant filter
     * if a tenant context is available.
     */
    @Before("execution(* com.fivucsas.identity.repository.*.*(..))")
    public void enableTenantFilter(JoinPoint joinPoint) {
        if (TenantContext.hasTenant()) {
            Session session = entityManager.unwrap(Session.class);
            Filter filter = session.enableFilter("tenantFilter");
            filter.setParameter("tenantId", TenantContext.requireCurrentTenant());

            log.trace("Tenant filter enabled for tenant: {} on method: {}",
                    TenantContext.getCurrentTenant(),
                    joinPoint.getSignature().getName());
        }
    }
}
