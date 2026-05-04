package com.fivucsas.identity.controller;

import com.fivucsas.identity.config.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Annotation + SecurityConfig regression guard for the idempotent
 * {@code DELETE /api/v1/auth/sessions/{sessionId}} endpoint added by the
 * 2026-04-24 login edge-case sweep (items #3 + #9).
 *
 * <p>The full controller-test slice in this module uses
 * {@code @AutoConfigureMockMvc(addFilters = false)} (see
 * {@link AuthSessionControllerListTest}). Per
 * {@code feedback_pr_review_workflow.md} we must NOT add new MockMvc
 * tests with filters disabled — that would silently hide a SecurityConfig
 * regression. We therefore verify the contract reflectively here:
 *
 * <ol>
 *   <li>The {@code @DeleteMapping("/{sessionId}")} mapping exists and binds
 *       the {@code sessionId} path variable as {@link UUID}.</li>
 *   <li>{@link SecurityConfig} contains an explicit
 *       {@code .requestMatchers(HttpMethod.DELETE, "/api/v1/auth/sessions/*")
 *       .authenticated()} entry — the path is NOT permitAll, so an
 *       attacker can't mass-cancel in-flight sessions by id-enumeration.</li>
 * </ol>
 *
 * <p>Full HTTP-status verification (204 / 404 / 401) is exercised by the
 * {@code AuthenticationFlowIntegrationTest} family running with
 * {@code RUN_INTEGRATION=true}.
 */
@DisplayName("AuthSessionController — DELETE /{sessionId} contract")
class AuthSessionDeleteControllerTest {

    @Test
    @DisplayName("@DeleteMapping(/{sessionId}) is present with UUID path var")
    void deleteMappingExistsWithUuidPathVar() throws Exception {
        Method method = AuthSessionController.class.getDeclaredMethod("deleteSession", UUID.class);

        DeleteMapping mapping = method.getAnnotation(DeleteMapping.class);
        assertThat(mapping)
                .as("deleteSession must carry @DeleteMapping (post-audit edge case #3)")
                .isNotNull();
        assertThat(mapping.value()).containsExactly("/{sessionId}");

        // First parameter must be a UUID-typed @PathVariable so client-supplied
        // string ids are validated by Spring's converter, not the handler body.
        var param = method.getParameters()[0];
        assertThat(param.getType()).isEqualTo(UUID.class);
        assertThat(param.getAnnotation(PathVariable.class))
                .as("sessionId must be bound via @PathVariable")
                .isNotNull();
    }

    @Test
    @DisplayName("SecurityConfig requires authn for DELETE /api/v1/auth/sessions/*")
    void securityConfig_requiresAuthnForDeletePath() throws Exception {
        // We can't boot the full Spring context here without dragging the
        // entire app, so we read the SecurityConfig source and assert the
        // request matcher line is present. This is a lightweight guard that
        // catches the most common regression — a refactor that drops the
        // line and silently regresses the path to a downstream catch-all
        // (which would be permitAll on /api/v1/** for some test profiles).
        java.nio.file.Path src = java.nio.file.Path.of(
                "src/main/java/com/fivucsas/identity/config/SecurityConfig.java");
        String body = java.nio.file.Files.readString(src);

        Pattern expected = Pattern.compile(
                "requestMatchers\\(\\s*HttpMethod\\.DELETE\\s*,\\s*\"/api/v1/auth/sessions/\\*\"\\s*\\)\\s*\\.authenticated\\(\\)",
                Pattern.MULTILINE);
        Matcher m = expected.matcher(body);
        assertThat(m.find())
                .as("SecurityConfig must require authn for DELETE /api/v1/auth/sessions/* — "
                        + "regression would let an attacker enumerate and cancel sessions by id")
                .isTrue();

        // SecurityConfig has at least one field, so reflection load works in CI.
        Field[] fields = SecurityConfig.class.getDeclaredFields();
        assertThat(fields.length).isGreaterThan(0);
    }
}
