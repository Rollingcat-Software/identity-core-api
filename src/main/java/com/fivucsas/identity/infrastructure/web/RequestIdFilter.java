package com.fivucsas.identity.infrastructure.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * P2.8b — Per-request correlation id.
 *
 * Reads the inbound {@code X-Request-Id} header (or generates a UUID if absent
 * or malformed), publishes it on the SLF4J MDC under the {@code requestId} key
 * so every log line emitted on the request thread carries the id, and echoes
 * it back to the caller via the {@code X-Request-Id} response header so a
 * client can quote it in a bug report.
 *
 * <p>Inbound header values are validated against
 * {@link CorrelationId#VALID_PATTERN} (alphanumerics + hyphen/underscore, max
 * 64 chars) to defend against log forging and HTTP response-splitting (CR/LF
 * injection). Anything that does not match is replaced with a fresh UUID.
 *
 * <p>Ordered to run before {@link com.fivucsas.identity.infrastructure.multitenancy.TenantContextFilter}
 * (Order=1) and {@link com.fivucsas.identity.security.JwtAuthenticationFilter}
 * so that auth/tenant log lines also include the request id.
 *
 * <p>The filter is registered exactly once via Spring Security's filter chain
 * (see {@code SecurityConfig#securityFilterChain}); Spring Boot's automatic
 * servlet-level registration is disabled by
 * {@link RequestIdFilter.Registration#disableAutoRegistration} below to avoid
 * double-execution that would clear the MDC before downstream filters run.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestIdFilter extends OncePerRequestFilter {

    /**
     * @deprecated use {@link CorrelationId#HEADER_NAME}.
     */
    @Deprecated
    public static final String HEADER_NAME = CorrelationId.HEADER_NAME;

    /**
     * @deprecated use {@link CorrelationId#MDC_KEY}.
     */
    @Deprecated
    public static final String MDC_KEY = CorrelationId.MDC_KEY;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String inbound = request.getHeader(CorrelationId.HEADER_NAME);
        String requestId = CorrelationId.isValid(inbound) ? inbound : UUID.randomUUID().toString();

        try {
            MDC.put(CorrelationId.MDC_KEY, requestId);
            response.setHeader(CorrelationId.HEADER_NAME, requestId);
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(CorrelationId.MDC_KEY);
        }
    }

    /**
     * Disables Spring Boot's automatic servlet-filter registration for
     * {@link RequestIdFilter}. The filter is still picked up as a
     * {@code @Component} bean and explicitly inserted into the
     * Spring Security filter chain, which is the only registration we want.
     *
     * <p>Without this, the filter would be invoked twice per request — once
     * at the servlet container layer and once inside the security chain —
     * with the outer invocation's {@code finally} block clearing the MDC
     * after downstream filters had already consumed it.
     */
    @Configuration
    static class Registration {

        @Bean
        public FilterRegistrationBean<RequestIdFilter> disableAutoRegistration(RequestIdFilter filter) {
            FilterRegistrationBean<RequestIdFilter> registration = new FilterRegistrationBean<>(filter);
            registration.setEnabled(false);
            return registration;
        }
    }
}
