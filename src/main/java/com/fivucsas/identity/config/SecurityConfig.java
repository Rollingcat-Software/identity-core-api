package com.fivucsas.identity.config;

import com.fivucsas.identity.infrastructure.multitenancy.TenantBindFromAuthFilter;
import com.fivucsas.identity.infrastructure.web.RequestIdFilter;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RbacPermissionEvaluator;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final RequestIdFilter requestIdFilter;
    private final TenantBindFromAuthFilter tenantBindFromAuthFilter;
    private final UserDetailsService userDetailsService;
    private final RbacPermissionEvaluator rbacPermissionEvaluator;

    @Value("${app.cors.allowed-origins:http://localhost:5173,http://localhost:3000,http://localhost:8080,http://localhost:4200,https://app.fivucsas.com}")
    private String allowedOrigins;

    @Value("${spring.profiles.active:dev}")
    private String activeProfile;

    @Value("${app.security.expose-docs:false}")
    private boolean exposeDocs;

    /**
     * Registers the custom RBAC PermissionEvaluator with Spring Security's
     * method security expression handler for hierarchical access control.
     */
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(rbacPermissionEvaluator);
        return handler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        // Public authentication endpoints
                        .requestMatchers(
                                "/api/v1/auth/register",
                                "/api/v1/auth/login",
                                "/api/v1/auth/refresh",
                                "/api/v1/auth/health",
                                "/api/v1/auth/forgot-password",
                                "/api/v1/auth/reset-password"
                        ).permitAll()

                        // N-step MFA flow (public — uses session token, not JWT)
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/mfa/step").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/mfa/send-otp").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/mfa/qr-generate").permitAll()
                        // Post-audit 2026-04-24: #3 cancel + #6 switch (pre-JWT state,
                        // MFA session token is the authenticator).
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/auth/mfa/session/*").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/mfa/switch-method").permitAll()

                        // OAuth 2.0 / OIDC public endpoints
                        .requestMatchers(
                                "/api/v1/oauth2/authorize",
                                "/api/v1/oauth2/authorize/complete",
                                "/api/v1/oauth2/token",
                                "/.well-known/openid-configuration",
                                "/.well-known/jwks.json"
                        ).permitAll()
                        // Public OAuth2 client branding metadata (hosted-login page)
                        .requestMatchers(HttpMethod.GET, "/api/v1/oauth2/clients/*/public").permitAll()

                        // WebAuthn authentication endpoints (pre-login, no JWT yet)
                        .requestMatchers(
                                "/api/v1/webauthn/authenticate-options",
                                "/api/v1/webauthn/authenticate"
                        ).permitAll()

                        // User session management endpoints require authentication
                        .requestMatchers("/api/v1/auth/sessions/my/**").authenticated()
                        .requestMatchers("/api/v1/auth/sessions/my").authenticated()

                        // Auth session endpoints: start, get status, and complete step are public
                        // (multi-step auth before JWT), but skip/cancel require authentication
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/sessions").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/sessions/*").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/sessions/*/steps/*").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/sessions/*/steps/*/skip").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/sessions/*/cancel").authenticated()
                        // Idempotent DELETE counterpart to /cancel (post-audit 2026-04-24
                        // login edge case #3). Authn required so an attacker can't enumerate
                        // and cancel arbitrary in-flight sessions by id.
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/auth/sessions/*").authenticated()

                        // QR session creation and polling must be public (unauthenticated clients)
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/qr/session").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/qr/session/**").permitAll()

                        // Public auth method listing
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth-methods", "/api/v1/auth-methods/**")
                        .permitAll()

                        // Guest invitation acceptance (token-based, no auth required)
                        .requestMatchers(
                                "/api/v1/guests/accept"
                        ).permitAll()

                        // Public self-service tenant onboarding (rate-limited per IP
                        // by RateLimitFilter). register = create org + admin;
                        // verify-email = token-based activation (no JWT).
                        .requestMatchers(HttpMethod.POST, "/api/v1/onboarding/register").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/onboarding/verify-email").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/onboarding/verify-email").permitAll()

                        // H2 console - restricted by profile and expose-docs flag (NEVER public)
                        .requestMatchers("/h2-console/**").access((authentication, context) ->
                                new org.springframework.security.authorization.AuthorizationDecision(exposeDocs && !isProductionProfile()))
                        // Swagger UI / OpenAPI specs - public (industry standard for API docs)
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**",
                                "/api-docs/**",
                                "/api-docs"
                        ).permitAll()
                        // Biometric health proxy: public so monitoring tools can reach it
                        .requestMatchers(HttpMethod.GET, "/api/v1/biometric/health").permitAll()

                        // Actuator: health is public, others require auth in prod
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/actuator/**").access((authentication, context) ->
                                new org.springframework.security.authorization.AuthorizationDecision(exposeDocs && !isProductionProfile()))

                        // Protected authentication endpoints
                        .requestMatchers(
                                "/api/v1/auth/me",
                                "/api/v1/auth/logout"
                        ).authenticated()

                        // All API endpoints require authentication
                        // Fine-grained RBAC enforced via @PreAuthorize and @rbac service
                        .requestMatchers("/api/v1/**").authenticated()

                        // Audit log endpoints - require authentication
                        .requestMatchers("/api/v1/audit-logs/**").authenticated()

                        // Enrollment endpoints - require authentication
                        .requestMatchers("/api/v1/enrollments/**").authenticated()

                        // All other requests require authentication
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType("application/json");
                            String path = request.getRequestURI();
                            String timestamp = java.time.Instant.now().toString();
                            response.getWriter().write(
                                    "{\"timestamp\":\"" + timestamp + "\",\"status\":401,\"error\":\"Unauthorized\",\"message\":\"Authentication required\",\"path\":\"" + path + "\",\"errors\":null}");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.setContentType("application/json");
                            String path = request.getRequestURI();
                            String timestamp = java.time.Instant.now().toString();
                            response.getWriter().write(
                                    "{\"timestamp\":\"" + timestamp + "\",\"status\":403,\"error\":\"Access Denied\",\"message\":\"You don't have permission to access this resource.\",\"path\":\"" + path + "\",\"errors\":null}");
                        })
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                // P2.8b: RequestIdFilter must run before auth so any log lines
                // emitted by JwtAuthenticationFilter carry the requestId MDC.
                .addFilterBefore(requestIdFilter, JwtAuthenticationFilter.class)
                // P0-SEC-1 (SECURITY_REVIEW_2026-05-01): TenantContextFilter
                // (Order(1)) trusts X-Tenant-ID at face value. Right after the
                // JWT auth filter has populated SecurityContextHolder, rebind
                // TenantContext to the JWT-derived tenantId so a forged header
                // can no longer swap tenants for an authenticated user.
                // ROOT keeps the legitimate cross-tenant override.
                .addFilterAfter(tenantBindFromAuthFilter, JwtAuthenticationFilter.class);

        // Only disable frame options for H2 console in non-prod profiles
        if (!isProductionProfile()) {
            http.headers(headers -> headers.frameOptions(fo -> fo.disable()));
        }

        return http.build();
    }

    private boolean isProductionProfile() {
        return "prod".equalsIgnoreCase(activeProfile)
                || "production".equalsIgnoreCase(activeProfile)
                || "docker".equalsIgnoreCase(activeProfile);
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Parse allowed origins from configuration (comma-separated)
        List<String> origins = Arrays.asList(allowedOrigins.split(","));
        configuration.setAllowedOrigins(origins);

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        // X-Request-Id: clients may forward an inbound correlation id; the server
        // also echoes it back in the response so JS can quote it in a bug report.
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "X-Tenant-ID", "X-CSRF-Token", "X-Request-Id"));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "X-Request-Id"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
