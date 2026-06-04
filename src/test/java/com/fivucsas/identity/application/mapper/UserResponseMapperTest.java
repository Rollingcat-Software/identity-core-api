package com.fivucsas.identity.application.mapper;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Focused tests for the deterministic primary-role selection used by both
 * {@code toResponse(entity.User)} and {@code fromDomain(domain.User)}.
 *
 * <p>Regression guard for the non-deterministic {@code roleNames.iterator().next()}
 * over a {@code HashSet} that let a multi-role user (e.g. a ROOT also holding
 * TENANT_ADMIN) render as an arbitrary/flickering role.
 */
@DisplayName("UserResponseMapper primary-role resolution")
class UserResponseMapperTest {

    @Test
    @DisplayName("empty roles default to USER (non-ROOT user_type)")
    void emptyRolesDefaultToUser() {
        assertThat(UserResponseMapper.resolvePrimaryRole(Set.of(), "TENANT_MEMBER")).isEqualTo("USER");
        assertThat(UserResponseMapper.resolvePrimaryRole(null, "TENANT_MEMBER")).isEqualTo("USER");
    }

    @Test
    @DisplayName("ROOT user_type ALWAYS renders as ROOT — even with no or only lower role rows")
    void rootUserTypeAlwaysRendersAsRoot() {
        // Platform tier is authoritative (mirrors the web: user.isRoot() == userType=='ROOT').
        // A ROOT promoted via user_type alone (empty / USER-only role rows) must NOT be
        // downgraded to USER on mobile — that hid QR-login/admin surfaces (glsm, 2026-06-04).
        assertThat(UserResponseMapper.resolvePrimaryRole(null, "ROOT")).isEqualTo("ROOT");
        assertThat(UserResponseMapper.resolvePrimaryRole(Set.of(), "ROOT")).isEqualTo("ROOT");
        assertThat(UserResponseMapper.resolvePrimaryRole(Set.of("USER"), "ROOT")).isEqualTo("ROOT");
        assertThat(UserResponseMapper.resolvePrimaryRole(Set.of("TENANT_ADMIN", "ROOT", "USER"), "ROOT")).isEqualTo("ROOT");
    }

    @Test
    @DisplayName("non-ROOT multi-role user picks highest-privilege role deterministically")
    void picksHighestPrivilegeRole() {
        Set<String> roles = Set.of("USER", "TENANT_ADMIN", "TENANT_VIEWER");
        assertThat(UserResponseMapper.resolvePrimaryRole(roles, "TENANT_ADMIN")).isEqualTo("TENANT_ADMIN");
    }

    @Test
    @DisplayName("selection is stable across different HashSet iteration orders")
    void selectionIsStableAcrossIterationOrders() {
        // Two sets with identical members but constructed in opposite insertion
        // orders must yield the same primary role.
        Set<String> a = new LinkedHashSet<>();
        a.add("USER");
        a.add("TENANT_ADMIN");
        a.add("TENANT_MEMBER");

        Set<String> b = new LinkedHashSet<>();
        b.add("TENANT_MEMBER");
        b.add("TENANT_ADMIN");
        b.add("USER");

        String roleA = UserResponseMapper.resolvePrimaryRole(a, "TENANT_ADMIN");
        String roleB = UserResponseMapper.resolvePrimaryRole(b, "TENANT_ADMIN");
        assertThat(roleA).isEqualTo("TENANT_ADMIN");
        assertThat(roleA).isEqualTo(roleB);
    }

    @Test
    @DisplayName("unknown roles rank last and break alphabetically")
    void unknownRolesRankLastAlphabetically() {
        assertThat(UserResponseMapper.resolvePrimaryRole(Set.of("ZEBRA_ROLE", "ALPHA_ROLE"), null))
                .isEqualTo("ALPHA_ROLE");
        // a known role always outranks an unknown one
        assertThat(UserResponseMapper.resolvePrimaryRole(Set.of("ZEBRA_ROLE", "USER"), null))
                .isEqualTo("USER");
    }

    @Test
    @DisplayName("legacy SUPER_ADMIN alias outranks tenant roles (ranking path, non-ROOT user_type)")
    void legacySuperAdminOutranksTenantRoles() {
        // user_type is NON-ROOT here so the privilege-ranking path runs (a ROOT
        // user_type now short-circuits to ROOT before ranking).
        assertThat(UserResponseMapper.resolvePrimaryRole(Set.of("SUPER_ADMIN", "TENANT_ADMIN"), "TENANT_ADMIN"))
                .isEqualTo("SUPER_ADMIN");
    }
}
