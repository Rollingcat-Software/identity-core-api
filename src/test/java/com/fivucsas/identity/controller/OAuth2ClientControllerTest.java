package com.fivucsas.identity.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T-P1-SEC Fix B (2026-05-07): annotation-level regression guard for the
 * {@link OAuth2ClientController} admin-only tightening.
 *
 * <p>Pre-fix every endpoint was {@code @PreAuthorize("isAuthenticated()")},
 * meaning any TENANT_MEMBER could mint OAuth2 client credentials for the
 * tenant — effectively a privilege-escalation primitive. All five endpoints
 * are now {@code @PreAuthorize("@rbac.isTenantAdmin()")}.
 *
 * <p>Following the pattern established by
 * {@link AuthFlowControllerSecurityTest}: annotation-level reflection avoids
 * the {@code addFilters=false} foot-gun (which would silently bypass method
 * security and hide regressions). Full-stack 403 vs 200 enforcement is
 * exercised by the broader Spring Security AOP machinery in the integration
 * suite.
 *
 * <p>{@code @rbac.isTenantAdmin()} resolves to true for {@code TENANT_ADMIN},
 * {@code ROOT} (formerly ROOT) via {@code UserType.isAtLeast}
 * (see {@link com.fivucsas.identity.security.RbacAuthorizationService}); a
 * {@code TENANT_MEMBER} principal therefore receives {@code 403 Forbidden}
 * from Spring Security's {@code AccessDeniedException} handler.
 */
@DisplayName("OAuth2ClientController @PreAuthorize admin-only sweep (T-P1-SEC Fix B)")
class OAuth2ClientControllerTest {

    private static final String EXPECTED_EXPRESSION = "@rbac.isTenantAdmin()";

    @Test
    @DisplayName("GET listClients — guarded by @rbac.isTenantAdmin()")
    void listClients_isGuardedByTenantAdmin() {
        assertGuarded("listClients", GetMapping.class);
    }

    @Test
    @DisplayName("POST registerClient — guarded by @rbac.isTenantAdmin()")
    void registerClient_isGuardedByTenantAdmin() {
        assertGuarded("registerClient", PostMapping.class);
    }

    @Test
    @DisplayName("GET getClient — guarded by @rbac.isTenantAdmin()")
    void getClient_isGuardedByTenantAdmin() {
        assertGuarded("getClient", GetMapping.class);
    }

    @Test
    @DisplayName("DELETE deleteClient — guarded by @rbac.isTenantAdmin()")
    void deleteClient_isGuardedByTenantAdmin() {
        assertGuarded("deleteClient", DeleteMapping.class);
    }

    @Test
    @DisplayName("PATCH toggleStatus — guarded by @rbac.isTenantAdmin()")
    void toggleStatus_isGuardedByTenantAdmin() {
        assertGuarded("toggleStatus", PatchMapping.class);
    }

    @Test
    @DisplayName("No endpoint may use the weak isAuthenticated() guard")
    void noEndpointUsesIsAuthenticated() {
        // Defence-in-depth: a partial revert that re-introduces
        // isAuthenticated() on a single endpoint would fail this test.
        for (Method m : OAuth2ClientController.class.getDeclaredMethods()) {
            PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
            if (ann == null) continue;
            assertThat(ann.value())
                    .as("Endpoint %s must not fall back to isAuthenticated()", m.getName())
                    .doesNotContain("isAuthenticated()");
        }
    }

    private static void assertGuarded(String methodName, Class<? extends Annotation> mappingAnn) {
        Method m = findMethod(methodName, mappingAnn);
        PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
        assertThat(ann)
                .as("%s must carry @PreAuthorize (T-P1-SEC Fix B)", methodName)
                .isNotNull();
        assertThat(ann.value())
                .as("%s @PreAuthorize value", methodName)
                .isEqualTo(EXPECTED_EXPRESSION);
    }

    private static Method findMethod(String name, Class<? extends Annotation> mappingAnn) {
        for (Method m : OAuth2ClientController.class.getDeclaredMethods()) {
            if (m.getName().equals(name) && m.isAnnotationPresent(mappingAnn)) {
                return m;
            }
        }
        throw new AssertionError("Method " + name + " with @" + mappingAnn.getSimpleName()
                + " not found on OAuth2ClientController");
    }
}
