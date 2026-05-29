package com.fivucsas.identity.infrastructure.multitenancy;

import jakarta.persistence.EntityManager;
import org.hibernate.Filter;
import org.hibernate.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantFilterBypass} — the helper that runs caller
 * self-resolution with the Hibernate {@code tenantFilter} suppressed.
 *
 * <p>The critical invariants:
 * <ul>
 *   <li>While {@code work} runs, {@link TenantContext} is cleared so
 *       {@code TenantHibernateAspect} does NOT re-enable the filter on the
 *       repository call(s) inside.</li>
 *   <li>After {@code work}, both {@link TenantContext} and the Hibernate filter
 *       are restored to their prior tenant so the rest of the request keeps its
 *       data scope.</li>
 *   <li>Restoration happens even if {@code work} throws.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TenantFilterBypass")
class TenantFilterBypassTest {

    @Mock
    private EntityManager entityManager;

    @Mock
    private Session session;

    @Mock
    private Filter filter;

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    private TenantFilterBypass newBypass() {
        when(entityManager.unwrap(Session.class)).thenReturn(session);
        return new TenantFilterBypass(entityManager);
    }

    @Test
    @DisplayName("filter enabled + tenant set → suppressed during work, restored after")
    void suppressesAndRestores() {
        UUID tenant = UUID.randomUUID();
        TenantContext.setCurrentTenant(tenant);
        when(session.getEnabledFilter("tenantFilter")).thenReturn(filter);
        when(session.enableFilter("tenantFilter")).thenReturn(filter);
        lenient().when(filter.setParameter(eq("tenantId"), eq(tenant))).thenReturn(filter);

        TenantFilterBypass bypass = newBypass();

        AtomicReference<UUID> contextDuringWork = new AtomicReference<>();
        String result = bypass.runWithoutTenantFilter(() -> {
            // Inside the work, the aspect must see a null TenantContext so it
            // won't re-enable the filter.
            contextDuringWork.set(TenantContext.getCurrentTenant());
            return "ok";
        });

        assertThat(result).isEqualTo("ok");
        assertThat(contextDuringWork.get()).as("context cleared during work").isNull();
        assertThat(TenantContext.getCurrentTenant()).as("context restored after").isEqualTo(tenant);

        verify(session).disableFilter("tenantFilter");
        verify(session).enableFilter("tenantFilter");
        verify(filter).setParameter("tenantId", tenant);
    }

    @Test
    @DisplayName("no filter enabled + no tenant → no-op around work")
    void noFilterNoTenant_noOp() {
        when(session.getEnabledFilter("tenantFilter")).thenReturn(null);

        TenantFilterBypass bypass = newBypass();

        String result = bypass.runWithoutTenantFilter(() -> "ok");

        assertThat(result).isEqualTo("ok");
        verify(session, never()).disableFilter("tenantFilter");
        verify(session, never()).enableFilter("tenantFilter");
    }

    @Test
    @DisplayName("restores filter + context even when work throws")
    void restoresOnException() {
        UUID tenant = UUID.randomUUID();
        TenantContext.setCurrentTenant(tenant);
        when(session.getEnabledFilter("tenantFilter")).thenReturn(filter);
        when(session.enableFilter("tenantFilter")).thenReturn(filter);
        lenient().when(filter.setParameter(eq("tenantId"), eq(tenant))).thenReturn(filter);

        TenantFilterBypass bypass = newBypass();

        assertThatThrownBy(() -> bypass.runWithoutTenantFilter(() -> {
            throw new IllegalStateException("boom");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(TenantContext.getCurrentTenant()).isEqualTo(tenant);
        verify(session).disableFilter("tenantFilter");
        verify(session).enableFilter("tenantFilter");
    }
}
