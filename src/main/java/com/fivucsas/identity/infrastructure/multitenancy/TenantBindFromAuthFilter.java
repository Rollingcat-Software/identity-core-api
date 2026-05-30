package com.fivucsas.identity.infrastructure.multitenancy;

import com.fivucsas.identity.security.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Re-binds {@link TenantContext} to the JWT-authenticated user's tenant,
 * overriding any tenant the request may have asserted via the
 * {@code X-Tenant-ID} header that {@link TenantContextFilter} processed
 * earlier in the chain.
 *
 * <p><b>Why a second filter:</b> the original {@code TenantContextFilter}
 * runs at {@code @Order(1)} — BEFORE Spring Security has populated the
 * {@link SecurityContextHolder} — and trusts the {@code X-Tenant-ID} header
 * after only verifying the tenant exists. That is a cross-tenant
 * confidentiality + integrity breach: any authenticated user can ask the
 * server to swap tenants by sending one extra header, and combined with the
 * JPA superuser bypassing PostgreSQL RLS, every tenant-scoped repository
 * query returns the foreign tenant's rows. SECURITY_REVIEW_2026-05-01.md §P0-1.</p>
 *
 * <p><b>Contract enforced here</b> (filter runs AFTER {@code JwtAuthenticationFilter}
 * via {@code SecurityConfig.addFilterAfter(...)}):</p>
 * <ul>
 *   <li>If the request is unauthenticated (public endpoint such as
 *       {@code /auth/login}, {@code /oauth2/authorize}, {@code /actuator/health}),
 *       leave whatever {@link TenantContextFilter} set in place — those
 *       endpoints already do not perform tenant-scoped reads.</li>
 *   <li>If the request is authenticated, derive the canonical tenantId
 *       from the {@link CustomUserDetails} principal. Compare it to whatever
 *       {@code TenantContextFilter} placed in {@link TenantContext}.
 *       <ul>
 *         <li>If they match, no change.</li>
 *         <li>If they differ AND the principal does not hold {@code ROOT},
 *             overwrite the context with the JWT-derived tenantId and log
 *             the attempted swap (potential exploit signal).</li>
 *         <li>If they differ AND the principal IS {@code ROOT}, accept
 *             the asserted tenantId — ROOT is the legitimate
 *             cross-tenant administration tier.</li>
 *       </ul>
 *   </li>
 * </ul>
 *
 * <p>Together with the pending RLS hardening (Task #27 — switch JPA
 * datasource to a non-superuser role + {@code FORCE ROW LEVEL SECURITY}
 * on all 9 multi-tenant tables), this filter is the application-layer half
 * of the tenant isolation contract.</p>
 */
@Component
@Slf4j
public class TenantBindFromAuthFilter extends OncePerRequestFilter {

    private static final String ROOT_ROLE = "ROLE_ROOT";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        try {
            rebindTenantFromAuth();
            filterChain.doFilter(request, response);
        } finally {
            // TenantContextFilter (the earlier one) owns the clear() call in
            // its own finally block. We do not clear here to avoid double-clear
            // races.
        }
    }

    private void rebindTenantFromAuth() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth.getPrincipal() == null) {
            return;
        }
        Object principal = auth.getPrincipal();
        if (!(principal instanceof CustomUserDetails details)) {
            // Anonymous or unrecognised principal — defer to whatever
            // TenantContextFilter set (typically null for public paths).
            return;
        }

        UUID jwtTenantId = details.getTenantId();
        UUID assertedTenantId = TenantContext.getCurrentTenant();

        if (jwtTenantId == null) {
            // Pathological — JWT-loaded user has no tenant. Don't trust the
            // header either. Clear and let downstream code handle.
            if (assertedTenantId != null) {
                log.warn("AUDIT: tenant-rebind cleared header-asserted tenantId={} for user {} with no JWT tenant",
                        assertedTenantId, details.getEmail());
                TenantContext.clear();
            }
            return;
        }

        if (assertedTenantId == null) {
            // Authenticated request without explicit X-Tenant-ID header — bind
            // to JWT tenant.
            TenantContext.setCurrentTenant(jwtTenantId);
            return;
        }

        if (jwtTenantId.equals(assertedTenantId)) {
            // Match — no action needed.
            return;
        }

        // Mismatch — only ROOT may assert a foreign tenantId.
        if (isRoot(auth)) {
            log.info("AUDIT: ROOT tenant override accepted — user={}, jwtTenant={}, assertedTenant={}",
                    details.getEmail(), jwtTenantId, assertedTenantId);
            // Leave TenantContext as TenantContextFilter set it.
            return;
        }

        // Non-ROOT attempting cross-tenant access — overwrite to the
        // JWT-derived tenantId and emit a warning for ops/security review.
        log.warn("AUDIT: tenant-rebind rejected cross-tenant assertion — user={}, jwtTenant={}, assertedTenant={}, role-set={}",
                details.getEmail(), jwtTenantId, assertedTenantId, auth.getAuthorities());
        TenantContext.setCurrentTenant(jwtTenantId);
    }

    private static boolean isRoot(Authentication auth) {
        for (GrantedAuthority a : auth.getAuthorities()) {
            if (ROOT_ROLE.equals(a.getAuthority())) {
                return true;
            }
        }
        return false;
    }
}
