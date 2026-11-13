package com.fivucsas.identity.infrastructure.multitenancy;

import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.security.CustomUserDetails;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * No tenant may outlive a request on a pooled server thread (PF-5 review).
 *
 * <p>{@link TenantContextFilter} skips {@code /actuator}, yet the security chain, and
 * with it {@link TenantBindFromAuthFilter}, still runs there. An authenticated
 * {@code GET /actuator/health} used to bind the caller's tenant and leave it on the
 * thread, so the next anonymous request served by that thread (for example a public
 * self-registration) ran in the caller's tenant.</p>
 */
@DisplayName("TenantContext does not leak from one request to the next on the same thread")
class TenantContextThreadLeakTest {

    private final TenantContextFilter contextFilter = new TenantContextFilter(mock(TenantRepository.class));
    private final TenantBindFromAuthFilter bindFilter = new TenantBindFromAuthFilter();

    private final UUID tenantA = UUID.randomUUID();

    @BeforeEach
    @AfterEach
    void reset() {
        TenantContext.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void authenticatedActuatorRequest_ThenAnonymousRequest_ShouldBindNoTenant() throws Exception {
        authenticateAs(tenantA, "ROLE_USER");
        UUID boundDuringHealth = serve("/actuator/health");
        SecurityContextHolder.clearContext();

        UUID boundDuringAnonymous = serve("/api/v1/auth/register");

        assertThat(boundDuringHealth).isEqualTo(tenantA);
        assertThat(boundDuringAnonymous).isNull();
        assertThat(TenantContext.getCurrentTenant()).isNull();
    }

    @Test
    void authenticatedActuatorRequest_ShouldLeaveNoTenantOnTheThread() throws Exception {
        authenticateAs(tenantA, "ROLE_USER");

        serve("/actuator/health");

        assertThat(TenantContext.getCurrentTenant()).isNull();
    }

    @Test
    void anonymousRequest_OnAThreadAlreadyHoldingATenant_ShouldBindNoTenant() throws Exception {
        TenantContext.setCurrentTenant(tenantA);

        UUID bound = serve("/api/v1/auth/register");

        assertThat(bound).isNull();
        assertThat(TenantContext.getCurrentTenant()).isNull();
    }

    @Test
    void rootRequestWithoutHeader_OnAThreadAlreadyHoldingAnotherTenant_ShouldBindItsOwnTenant() throws Exception {
        UUID rootHome = UUID.randomUUID();
        TenantContext.setCurrentTenant(tenantA);
        authenticateAs(rootHome, "ROLE_ROOT");

        UUID bound = serve("/api/v1/users");

        assertThat(bound).isEqualTo(rootHome);
        assertThat(TenantContext.getCurrentTenant()).isNull();
    }

    /** Runs one request through both filters in their real order; returns the tenant the servlet saw. */
    private UUID serve(String uri) throws Exception {
        AtomicReference<UUID> seen = new AtomicReference<>();
        HttpServlet servlet = new HttpServlet() {
            @Override
            protected void service(HttpServletRequest req, HttpServletResponse resp) {
                seen.set(TenantContext.getCurrentTenant());
            }
        };
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        new MockFilterChain(servlet, contextFilter, bindFilter)
                .doFilter(request, new MockHttpServletResponse());
        return seen.get();
    }

    private static void authenticateAs(UUID tenantId, String role) {
        CustomUserDetails details = new CustomUserDetails(
                UUID.randomUUID(), "caller@example.com", "{noop}irrelevant", tenantId, true,
                List.of(new SimpleGrantedAuthority(role)));
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(details, null, details.getAuthorities()));
    }
}
