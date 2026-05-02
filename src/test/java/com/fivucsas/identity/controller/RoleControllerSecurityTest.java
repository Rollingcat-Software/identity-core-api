package com.fivucsas.identity.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Annotation-level regression guard for P0-SEC-4 (SECURITY_REVIEW_2026-05-01).
 *
 * <p>{@code RoleController.createRole} previously accepted {@code tenantId}
 * straight from the JSON request body and persisted it without any ownership
 * check, allowing a TENANT_ADMIN of tenant A (with implicit {@code role:create})
 * to mint a role inside tenant B's namespace. Same shape as P0-1 but at the
 * controller layer rather than the JWT-binding filter.
 *
 * <p>This codebase's controller-slice tests run with
 * {@code @AutoConfigureMockMvc(addFilters = false)} which silently disables
 * Spring Security method-security AOP — adding a slice test would not catch
 * a regression. We mirror {@link AuthFlowControllerSecurityTest}'s reflective
 * pattern instead. End-to-end 403/201 enforcement is covered by the boot
 * integration tests that bring up the real {@code SecurityConfig}.
 */
@DisplayName("RoleController @PreAuthorize sweep (P0-SEC-4)")
class RoleControllerSecurityTest {

    @Test
    @DisplayName("POST createRole — must gate body tenantId via @rbac.canAccessTenant(#request.tenantId)")
    void createRole_isGuardedByTenantOwnership() throws Exception {
        Method m = findMethod("createRole", PostMapping.class);
        PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
        assertThat(ann)
                .as("createRole must carry @PreAuthorize (P0-SEC-4 fix)")
                .isNotNull();
        assertThat(ann.value())
                .as("expression must check both 'role:create' permission AND tenant ownership")
                .contains("@rbac.hasPermission('role:create')")
                .contains("@rbac.canAccessTenant(#request.tenantId)")
                .contains(" and ");
    }

    @Test
    @DisplayName("GET getRolesByTenant — must gate path tenantId via @rbac.canAccessTenant(#tenantId)")
    void getRolesByTenant_isGuardedByTenantOwnership() throws Exception {
        Method m = findMethod("getRolesByTenant", GetMapping.class);
        PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
        assertThat(ann)
                .as("getRolesByTenant must carry @PreAuthorize (P0-SEC-4 sweep)")
                .isNotNull();
        assertThat(ann.value())
                .as("expression must check tenant ownership on the path variable")
                .contains("@rbac.hasPermission('role:read')")
                .contains("@rbac.canAccessTenant(#tenantId)")
                .contains(" and ");
    }

    private static Method findMethod(String name, Class<? extends java.lang.annotation.Annotation> mappingAnn) {
        for (Method m : RoleController.class.getDeclaredMethods()) {
            if (m.getName().equals(name) && m.isAnnotationPresent(mappingAnn)) {
                return m;
            }
        }
        throw new AssertionError("Method " + name + " with @" + mappingAnn.getSimpleName()
                + " not found on RoleController");
    }
}
