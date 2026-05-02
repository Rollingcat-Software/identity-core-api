package com.fivucsas.identity.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Annotation-level regression guard for P0-SEC-4 sibling sweep
 * (SECURITY_REVIEW_2026-05-01). {@code DeviceController.registerDevice}
 * previously took {@code tenantId} as a {@code @RequestParam} without any
 * ownership check — the {@code device:register} permission alone could be
 * exploited by a tenant admin in tenant A to register a device into tenant
 * B's namespace.
 *
 * <p>See {@link AuthFlowControllerSecurityTest} for the rationale behind the
 * reflective annotation-pin approach (controller slices use
 * {@code addFilters = false} which hides @PreAuthorize regressions).
 */
@DisplayName("DeviceController @PreAuthorize sweep (P0-SEC-4 sibling)")
class DeviceControllerSecurityTest {

    @Test
    @DisplayName("POST registerDevice — must gate request-param tenantId via @rbac.canAccessTenant(#tenantId)")
    void registerDevice_isGuardedByTenantOwnership() throws Exception {
        Method m = findMethod("registerDevice", PostMapping.class);
        PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
        assertThat(ann)
                .as("registerDevice must carry @PreAuthorize (P0-SEC-4 fix)")
                .isNotNull();
        assertThat(ann.value())
                .as("expression must combine device:register permission with tenant ownership")
                .contains("device:register")
                .contains("@rbac.canAccessTenant(#tenantId)")
                .contains(" and ");
    }

    private static Method findMethod(String name, Class<? extends java.lang.annotation.Annotation> mappingAnn) {
        for (Method m : DeviceController.class.getDeclaredMethods()) {
            if (m.getName().equals(name) && m.isAnnotationPresent(mappingAnn)) {
                return m;
            }
        }
        throw new AssertionError("Method " + name + " with @" + mappingAnn.getSimpleName()
                + " not found on DeviceController");
    }
}
