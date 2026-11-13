package com.fivucsas.identity.infrastructure.multitenancy;

import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.repository.TenantRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

/**
 * Filter to extract tenant from request and set in TenantContext.
 *
 * Tenant can be identified by:
 * - X-Tenant-ID header (UUID)
 * - X-Tenant-Slug header (string slug)
 * - Subdomain (e.g., tenant1.example.com)
 *
 * Following principles:
 * - Single Responsibility: Only handles tenant extraction
 * - Open/Closed: Can add new extraction methods
 *
 * <p><b>Ordering is a security invariant.</b> This filter only records the tenant a
 * client ASSERTS. {@link TenantBindFromAuthFilter}, inside the Spring Security chain,
 * then rebinds it to the tenant of the verified token for every non-ROOT caller. That
 * works only when this filter runs BEFORE the security chain, which Spring Boot
 * registers at {@link SecurityProperties#DEFAULT_FILTER_ORDER}. At {@code @Order(1)} it
 * ran after the chain, so the header overwrote the token tenant for every caller and
 * the rebind never took effect (AX-5 cross-tenant run). Being outermost also makes the
 * {@code finally} below the last word on clearing the context.</p>
 */
@Component
@Order(TenantContextFilter.ORDER)
@RequiredArgsConstructor
@Slf4j
public class TenantContextFilter extends OncePerRequestFilter {

    /** Runs before the Spring Security filter chain; see the class comment. */
    public static final int ORDER = SecurityProperties.DEFAULT_FILTER_ORDER - 10;

    private static final String TENANT_ID_HEADER = "X-Tenant-ID";
    private static final String TENANT_SLUG_HEADER = "X-Tenant-Slug";

    private final TenantRepository tenantRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        try {
            UUID tenantId = extractTenantId(request);

            if (tenantId != null) {
                TenantContext.setCurrentTenant(tenantId);
                log.debug("Tenant context set: {}", tenantId);
            } else {
                log.debug("No tenant context for request: {}", request.getRequestURI());
            }

            filterChain.doFilter(request, response);

        } finally {
            // Always clear context to prevent memory leaks
            TenantContext.clear();
        }
    }

    /**
     * Extracts tenant ID from request.
     * Priority: ID header > Slug header > Subdomain
     */
    private UUID extractTenantId(HttpServletRequest request) {
        // Try X-Tenant-ID header first
        String tenantIdHeader = request.getHeader(TENANT_ID_HEADER);
        if (tenantIdHeader != null && !tenantIdHeader.isEmpty()) {
            try {
                UUID tenantId = UUID.fromString(tenantIdHeader);
                // Validate tenant exists
                if (tenantRepository.findById(tenantId).isPresent()) {
                    return tenantId;
                }
                log.warn("Invalid tenant ID in header: {}", tenantIdHeader);
            } catch (IllegalArgumentException e) {
                log.warn("Malformed tenant ID in header: {}", tenantIdHeader);
            }
        }

        // Try X-Tenant-Slug header
        String tenantSlugHeader = request.getHeader(TENANT_SLUG_HEADER);
        if (tenantSlugHeader != null && !tenantSlugHeader.isEmpty()) {
            Optional<Tenant> tenant = tenantRepository.findBySlug(tenantSlugHeader);
            if (tenant.isPresent()) {
                return tenant.get().getId();
            }
            log.warn("Invalid tenant slug in header: {}", tenantSlugHeader);
        }

        // Try subdomain extraction
        String host = request.getServerName();
        if (host != null && host.contains(".")) {
            String subdomain = host.split("\\.")[0];
            // Ignore common subdomains
            if (!subdomain.equals("www") && !subdomain.equals("api")) {
                Optional<Tenant> tenant = tenantRepository.findBySlug(subdomain);
                if (tenant.isPresent()) {
                    return tenant.get().getId();
                }
            }
        }

        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Skip tenant filtering for public endpoints
        return path.startsWith("/actuator") ||
               path.startsWith("/swagger") ||
               path.startsWith("/v3/api-docs") ||
               path.equals("/health");
    }
}
