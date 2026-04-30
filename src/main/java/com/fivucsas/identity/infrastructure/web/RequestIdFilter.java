package com.fivucsas.identity.infrastructure.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * P2.8b — Per-request correlation id.
 *
 * Reads the inbound {@code X-Request-Id} header (or generates a UUID if absent),
 * publishes it on the SLF4J MDC under the {@code requestId} key so every log
 * line emitted on the request thread carries the id, and echoes it back to the
 * caller via the {@code X-Request-Id} response header so a client can quote it
 * in a bug report.
 *
 * Ordered to run before {@link com.fivucsas.identity.infrastructure.multitenancy.TenantContextFilter}
 * (Order=1) and {@link com.fivucsas.identity.security.JwtAuthenticationFilter}
 * so that auth/tenant log lines also include the request id.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestIdFilter extends OncePerRequestFilter {

    public static final String HEADER_NAME = "X-Request-Id";
    public static final String MDC_KEY = "requestId";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String requestId = request.getHeader(HEADER_NAME);
        if (requestId == null || requestId.isBlank()) {
            requestId = UUID.randomUUID().toString();
        }

        try {
            MDC.put(MDC_KEY, requestId);
            response.setHeader(HEADER_NAME, requestId);
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }
}
