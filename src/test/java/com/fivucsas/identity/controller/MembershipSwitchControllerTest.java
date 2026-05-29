package com.fivucsas.identity.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.lang.reflect.Method;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Annotation + SecurityConfig regression guard for
 * {@code POST /api/v1/auth/switch-membership} (Phase-5 membership switch).
 *
 * <p>Per {@code feedback_pr_review_workflow.md} we do NOT add a MockMvc slice
 * with {@code addFilters=false} for a new auth-sensitive endpoint — that would
 * silently hide a SecurityConfig regression. Instead we verify the contract
 * reflectively + by reading the SecurityConfig source:
 *
 * <ol>
 *   <li>the {@code @PostMapping("/switch-membership")} handler exists, takes a
 *       {@code @RequestBody} request DTO + the raw {@link HttpServletRequest}
 *       (needed to carry over amr/auth_time from the current token);</li>
 *   <li>SecurityConfig does NOT {@code permitAll()} the path — so it falls
 *       through to {@code .requestMatchers("/api/v1/**").authenticated()}. A
 *       membership switch is an auth-escalation surface; an anonymous caller
 *       must never reach it.</li>
 * </ol>
 *
 * <p>Full HTTP-status verification (200 / 403 / 409) is exercised by
 * {@link com.fivucsas.identity.application.service.SwitchMembershipServiceTest}
 * (service-level) + the GlobalExceptionHandler mapping.
 */
@DisplayName("MembershipSwitchController — POST /switch-membership contract")
class MembershipSwitchControllerTest {

    @Test
    @DisplayName("@PostMapping(/switch-membership) present with @RequestBody + HttpServletRequest")
    void postMappingExists() throws Exception {
        Method handler = MembershipSwitchController.class.getDeclaredMethod(
                "switchMembership",
                MembershipSwitchController.SwitchMembershipRequest.class,
                HttpServletRequest.class);

        PostMapping mapping = handler.getAnnotation(PostMapping.class);
        assertThat(mapping)
                .as("switchMembership must carry @PostMapping")
                .isNotNull();
        assertThat(mapping.value()).containsExactly("/switch-membership");

        // First param is the JSON body DTO.
        var bodyParam = handler.getParameters()[0];
        assertThat(bodyParam.getAnnotation(RequestBody.class))
                .as("request body must be bound via @RequestBody")
                .isNotNull();
        // Second param is the raw request (carry amr/auth_time from current token).
        assertThat(handler.getParameters()[1].getType()).isEqualTo(HttpServletRequest.class);
    }

    @Test
    @DisplayName("SecurityConfig does NOT permitAll /api/v1/auth/switch-membership")
    void securityConfig_doesNotPermitAllSwitchMembership() throws Exception {
        java.nio.file.Path src = java.nio.file.Path.of(
                "src/main/java/com/fivucsas/identity/config/SecurityConfig.java");
        String body = java.nio.file.Files.readString(src);

        // Any permitAll mention of the switch path is a regression: the endpoint
        // must remain behind the authenticated /api/v1/** catch-all.
        Pattern leaked = Pattern.compile(
                "switch-membership[\\s\\S]{0,80}?permitAll",
                Pattern.MULTILINE);
        assertThat(leaked.matcher(body).find())
                .as("switch-membership must NOT be permitAll — it is an auth-escalation surface")
                .isFalse();

        // And the catch-all authenticated rule that protects it must still exist.
        Pattern catchAll = Pattern.compile(
                "requestMatchers\\(\\s*\"/api/v1/\\*\\*\"\\s*\\)\\s*\\.authenticated\\(\\)");
        assertThat(catchAll.matcher(body).find())
                .as("the /api/v1/** authenticated catch-all must exist to protect the endpoint")
                .isTrue();
    }
}
