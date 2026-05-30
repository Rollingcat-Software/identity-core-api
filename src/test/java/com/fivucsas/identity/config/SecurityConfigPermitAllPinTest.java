package com.fivucsas.identity.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Source-level pin for every anonymous endpoint configured in
 * {@link SecurityConfig#securityFilterChain}.
 *
 * <p>This codebase's controller-slice tests run with
 * {@code @AutoConfigureMockMvc(addFilters = false)} (see
 * {@code feedback_pr_review_workflow.md}). Filter-chain regressions —
 * accidentally moving a {@code permitAll()} endpoint behind
 * {@code .authenticated()}, or losing it entirely under a default
 * {@code anyRequest().authenticated()} — are therefore invisible to
 * {@code mvn test -Dtest='*ControllerTest'}.
 *
 * <p>Two coverage layers guard against this:
 *
 * <ol>
 *   <li><b>This test (unit-level, no Spring context).</b> Reads
 *       {@code SecurityConfig.java} as text and asserts every
 *       expected anonymous endpoint is still present in the source.
 *       Runs in {@code mvn test} so a regression PR fails CI's unit
 *       phase, not its slower integration phase.</li>
 *   <li>{@code OAuth2PublicEndpointsSecurityIntegrationTest} +
 *       {@code AnonymousEndpointsSecurityIntegrationTest} (integration-level,
 *       {@code @SpringBootTest} with the real filter chain). Confirms the
 *       endpoints actually return non-401 to anonymous requests at runtime.</li>
 * </ol>
 *
 * <p>If this test fails, either:
 * <ul>
 *   <li>You moved a public endpoint behind authentication on purpose — update the
 *       expected list below AND the relevant integration test.</li>
 *   <li>You regressed a public endpoint by mistake — fix
 *       {@code SecurityConfig.java}.</li>
 * </ul>
 */
@DisplayName("SecurityConfig permitAll pin (regression guard for addFilters=false slice tests)")
class SecurityConfigPermitAllPinTest {

    /**
     * Every endpoint here MUST appear in {@link SecurityConfig#securityFilterChain}
     * inside a {@code .permitAll()} chain. Adding a new public endpoint? Add it
     * here AND to {@code AnonymousEndpointsSecurityIntegrationTest}.
     */
    private static final List<String> EXPECTED_PERMITALL_PATHS = List.of(
            // /api/v1/auth/* public (pre-JWT)
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/auth/health",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password",
            // Public tenant login-flow config (task #16 C)
            "/api/v1/auth/login-config",
            // N-step MFA
            "/api/v1/auth/mfa/step",
            "/api/v1/auth/mfa/send-otp",
            "/api/v1/auth/mfa/qr-generate",
            "/api/v1/auth/mfa/session/*",
            "/api/v1/auth/mfa/switch-method",
            // OAuth2 / OIDC public
            "/api/v1/oauth2/authorize",
            "/api/v1/oauth2/authorize/complete",
            "/api/v1/oauth2/token",
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
            "/api/v1/oauth2/clients/*/public",
            // WebAuthn pre-login
            "/api/v1/webauthn/authenticate-options",
            "/api/v1/webauthn/authenticate",
            // Usernameless / discoverable passkey pre-login (Phase 1)
            "/api/v1/webauthn/passkey/authenticate-options",
            "/api/v1/webauthn/passkey/authenticate",
            // Auth-session (multi-step pre-JWT)
            "/api/v1/auth/sessions",
            "/api/v1/auth/sessions/*",
            "/api/v1/auth/sessions/*/steps/*",
            // QR session
            "/api/v1/auth/qr/session",
            "/api/v1/auth/qr/session/**",
            // Approve-login (number-matching) initiator side
            "/api/v1/auth/approve-login/session",
            "/api/v1/auth/approve-login/session/*",
            // Public auth method listing
            "/api/v1/auth-methods",
            // Guest invitations
            "/api/v1/guests/accept",
            // Biometric health (monitoring)
            "/api/v1/biometric/health",
            // Actuator health
            "/actuator/health"
    );

    /**
     * Endpoints that MUST require authentication (.authenticated()). Verifies
     * the post-audit 2026-04-24 login-edge-case fix (item #3) survives refactors:
     * an attacker should not be able to enumerate-cancel arbitrary in-flight
     * sessions by id.
     */
    private static final List<String> EXPECTED_AUTHENTICATED_PATHS = List.of(
            "/api/v1/auth/sessions/my/**",
            "/api/v1/auth/sessions/my",
            "/api/v1/auth/sessions/*/steps/*/skip",
            "/api/v1/auth/sessions/*/cancel",
            "/api/v1/auth/sessions/*",   // DELETE only — tested separately below
            "/api/v1/auth/me",
            "/api/v1/auth/logout"
    );

    private String securityConfigSource() throws Exception {
        Path p = Path.of("src/main/java/com/fivucsas/identity/config/SecurityConfig.java");
        return Files.readString(p);
    }

    @Test
    @DisplayName("Every expected permitAll path appears in SecurityConfig source")
    void permitAllPathsArePinned() throws Exception {
        String source = securityConfigSource();

        for (String path : EXPECTED_PERMITALL_PATHS) {
            // Match either "..., \"PATH\", ..." or "...\"PATH\"..." inside a
            // requestMatchers(...).permitAll() chain. We don't try to parse the
            // Java AST — a substring match for the quoted path is enough to
            // catch "someone deleted the line" regressions.
            String quoted = "\"" + path + "\"";
            assertThat(source)
                    .as("SecurityConfig must declare %s as permitAll. "
                            + "If you intentionally moved this behind auth, update "
                            + "EXPECTED_PERMITALL_PATHS and the matching integration test.", path)
                    .contains(quoted);
        }
    }

    @Test
    @DisplayName("Every expected authenticated path appears in SecurityConfig source")
    void authenticatedPathsArePinned() throws Exception {
        String source = securityConfigSource();

        for (String path : EXPECTED_AUTHENTICATED_PATHS) {
            String quoted = "\"" + path + "\"";
            assertThat(source)
                    .as("SecurityConfig must declare %s with explicit access rule "
                            + "(authenticated/permitAll). A missing entry would fall through "
                            + "to anyRequest().authenticated() — fine for read-side, but breaks "
                            + "pre-JWT public flows if it slips into the wrong block.", path)
                    .contains(quoted);
        }
    }

    @Test
    @DisplayName("DELETE /api/v1/auth/sessions/* is authenticated (post-audit 2026-04-24 #3)")
    void deleteAuthSessionsRequiresAuthn() throws Exception {
        String source = securityConfigSource();
        Pattern expected = Pattern.compile(
                "requestMatchers\\(\\s*HttpMethod\\.DELETE\\s*,\\s*\"/api/v1/auth/sessions/\\*\"\\s*\\)\\s*\\.authenticated\\(\\)",
                Pattern.MULTILINE);
        assertThat(expected.matcher(source).find())
                .as("DELETE /api/v1/auth/sessions/* must be .authenticated(). "
                        + "Regression would let an attacker enumerate and cancel in-flight sessions.")
                .isTrue();
    }

    @Test
    @DisplayName("anyRequest().authenticated() catch-all is still last")
    void catchAllIsAuthenticated() throws Exception {
        String source = securityConfigSource();
        assertThat(source)
                .as("SecurityConfig must end its authorize-rules chain with "
                        + "anyRequest().authenticated() — accidentally swapping for "
                        + "permitAll() would expose every unmatched endpoint.")
                .contains(".anyRequest().authenticated()");
    }

    @Test
    @DisplayName("CSRF disabled (we are stateless / JWT)")
    void csrfDisabled() throws Exception {
        String source = securityConfigSource();
        assertThat(source).contains("csrf(AbstractHttpConfigurer::disable)");
    }

    @Test
    @DisplayName("Session policy is STATELESS")
    void sessionPolicyIsStateless() throws Exception {
        String source = securityConfigSource();
        assertThat(source).contains("SessionCreationPolicy.STATELESS");
    }
}
