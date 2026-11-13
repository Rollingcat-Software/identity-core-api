package com.fivucsas.identity.infrastructure.multitenancy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.annotation.OrderUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link TenantContextFilter} binds the tenant a client asserts in {@code X-Tenant-ID};
 * {@link TenantBindFromAuthFilter}, inside the Spring Security chain, then rebinds it
 * to the tenant of the verified token for every non-ROOT caller. That only works when
 * the header filter runs BEFORE the security chain. At {@code @Order(1)} it ran after
 * the chain (registered at {@link SecurityProperties#DEFAULT_FILTER_ORDER}), so the
 * header overwrote the token tenant for every caller.
 */
@DisplayName("TenantContextFilter runs before the Spring Security filter chain")
class TenantContextFilterOrderTest {

    @Test
    void order_WhenRegisteredAsServletFilter_ShouldPrecedeTheSecurityChain() {
        Integer order = OrderUtils.getOrder(TenantContextFilter.class);

        assertThat(order).isNotNull();
        assertThat(order).isLessThan(SecurityProperties.DEFAULT_FILTER_ORDER);
    }
}
