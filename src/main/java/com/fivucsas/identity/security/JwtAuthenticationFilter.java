package com.fivucsas.identity.security;

import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT Authentication Filter that intercepts requests and validates JWT tokens.
 * This filter runs once per request and validates the Authorization header.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final CachePort cachePort;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // Skip if no Authorization header or not a Bearer token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt = authHeader.substring(7);
            final String userEmail = jwtService.extractEmail(jwt);

            // If email extracted and user not already authenticated
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Check blacklist before loading user details (fail-closed: reject if Redis unavailable)
                String jti = jwtService.extractJti(jwt);
                if (jti == null) {
                    log.warn("Rejected token without JTI claim for user: {}", userEmail);
                    filterChain.doFilter(request, response);
                    return;
                }
                try {
                    if (cachePort.existsFailClosed("blacklist:" + jti)) {
                        log.warn("Rejected blacklisted token (JTI: {}) for user: {}", jti, userEmail);
                        filterChain.doFilter(request, response);
                        return;
                    }
                } catch (com.fivucsas.identity.domain.exception.CacheUnavailableException e) {
                    log.error("Redis unavailable for blacklist check — rejecting token (fail-closed) for user: {}", userEmail);
                    SecurityContextHolder.clearContext();
                    filterChain.doFilter(request, response);
                    return;
                }

                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

                // Validate token. SECURITY (2026-06-01, LOGIC_AUDIT): also reject a
                // structurally-valid token whose account is no longer enabled
                // (CustomUserDetailsService maps SUSPENDED/INACTIVE → enabled=false),
                // so an admin suspension takes effect on already-issued tokens too.
                if (jwtService.isTokenValid(jwt, userEmail) && userDetails.isEnabled()) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.debug("User {} authenticated successfully", userEmail);
                } else {
                    log.warn("Invalid JWT token for user: {}", userEmail);
                }
            }
        } catch (Exception e) {
            log.error("JWT authentication error: {}", e.getMessage());
            // Clear security context on error
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
