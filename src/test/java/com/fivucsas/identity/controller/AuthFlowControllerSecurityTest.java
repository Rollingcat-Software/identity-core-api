package com.fivucsas.identity.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Annotation-level regression guard for the Phase H1 admin
 * {@code @PreAuthorize} sweep on {@link AuthFlowController}.
 *
 * <p>The existing controller-layer tests in this module run with
 * {@code @AutoConfigureMockMvc(addFilters = false)} which bypasses Spring
 * Security entirely (filters AND method-security AOP, since the security
 * config is excluded from the test slice). Adding more {@code addFilters=false}
 * tests would simply hide regressions in the {@code @PreAuthorize} expressions.
 *
 * <p>Instead we reflectively assert that every mutating endpoint
 * (POST/PUT/DELETE) on this controller carries the expected
 * {@code @rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)}
 * authorization expression. This catches the failure mode
 * (silent removal / weakening of the annotation) without needing the full
 * Spring Security AOP stack.
 *
 * <p>Full-stack 403/200 verification is covered by the
 * {@code AuthenticationFlowIntegrationTest} (and family) which boot the
 * real {@link com.fivucsas.identity.config.SecurityConfig} via
 * {@code @SpringBootTest}.
 */
@DisplayName("AuthFlowController @PreAuthorize sweep (Phase H1)")
class AuthFlowControllerSecurityTest {

    private static final String EXPECTED_EXPRESSION =
            "@rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)";

    @Test
    @DisplayName("POST createFlow — guarded by @rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)")
    void createFlow_isGuardedByTenantAdmin() throws Exception {
        Method m = findMethod("createFlow", PostMapping.class);
        PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
        assertThat(ann)
                .as("createFlow must carry @PreAuthorize (Phase H1 admin sweep)")
                .isNotNull();
        assertThat(ann.value()).isEqualTo(EXPECTED_EXPRESSION);
    }

    @Test
    @DisplayName("PUT updateFlow — guarded by @rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)")
    void updateFlow_isGuardedByTenantAdmin() throws Exception {
        Method m = findMethod("updateFlow", PutMapping.class);
        PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
        assertThat(ann)
                .as("updateFlow must carry @PreAuthorize (Phase H1 admin sweep)")
                .isNotNull();
        assertThat(ann.value()).isEqualTo(EXPECTED_EXPRESSION);
    }

    @Test
    @DisplayName("DELETE deleteFlow — guarded by @rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)")
    void deleteFlow_isGuardedByTenantAdmin() throws Exception {
        Method m = findMethod("deleteFlow", DeleteMapping.class);
        PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
        assertThat(ann)
                .as("deleteFlow must carry @PreAuthorize (Phase H1 admin sweep)")
                .isNotNull();
        assertThat(ann.value()).isEqualTo(EXPECTED_EXPRESSION);
    }

    @Test
    @DisplayName("Mutating expression must include both isTenantAdmin AND canAccessTenant — neither alone is sufficient")
    void expression_combinesAdminAndTenantScope() {
        // Defence-in-depth: a regression that drops either half of the AND
        // would leak access. We pin the exact expression so a partial revert
        // (e.g. back to '@rbac.canAccessTenant(#tenantId)') fails this test.
        assertThat(EXPECTED_EXPRESSION)
                .contains("@rbac.isTenantAdmin()")
                .contains("@rbac.canAccessTenant(#tenantId)")
                .contains(" and ");
    }

    private static Method findMethod(String name, Class<? extends java.lang.annotation.Annotation> mappingAnn) {
        for (Method m : AuthFlowController.class.getDeclaredMethods()) {
            if (m.getName().equals(name) && m.isAnnotationPresent(mappingAnn)) {
                return m;
            }
        }
        throw new AssertionError("Method " + name + " with @" + mappingAnn.getSimpleName()
                + " not found on AuthFlowController");
    }
}
