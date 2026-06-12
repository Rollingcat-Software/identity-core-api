package com.fivucsas.identity.application.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PuzzleLayerPolicy} — the kill-switch that gates the
 * PUZZLE liveness layer (sub-project B, Phase 1).
 *
 * <p>Mirrors {@link ClientSideEmbeddingPolicyTest} in structure: proves the
 * default-OFF behaviour (PUZZLE absent from the catalog for every tenant), the
 * global master-switch ON behaviour, and the per-tenant canary list.</p>
 */
@DisplayName("PuzzleLayerPolicy")
class PuzzleLayerPolicyTest {

    private static final UUID TENANT_A = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID TENANT_B = UUID.fromString("22222222-2222-2222-2222-222222222222");

    @Nested
    @DisplayName("default OFF (flag false, no canary)")
    class DefaultOff {

        private final PuzzleLayerPolicy policy = new PuzzleLayerPolicy(false, "");

        @Test
        @DisplayName("isGloballyEnabled() is false")
        void globalOff() {
            assertThat(policy.isGloballyEnabled()).isFalse();
        }

        @Test
        @DisplayName("isEnabledFor() is false for any tenant")
        void perTenantOff() {
            assertThat(policy.isEnabledFor(TENANT_A)).isFalse();
            assertThat(policy.isEnabledFor(TENANT_B)).isFalse();
            assertThat(policy.isEnabledFor(null)).isFalse();
        }
    }

    @Nested
    @DisplayName("global ON (master switch true)")
    class GlobalOn {

        private final PuzzleLayerPolicy policy = new PuzzleLayerPolicy(true, "");

        @Test
        @DisplayName("isGloballyEnabled() is true")
        void globalOn() {
            assertThat(policy.isGloballyEnabled()).isTrue();
        }

        @Test
        @DisplayName("isEnabledFor() is true for every tenant")
        void perTenantOn() {
            assertThat(policy.isEnabledFor(TENANT_A)).isTrue();
            assertThat(policy.isEnabledFor(TENANT_B)).isTrue();
        }
    }

    @Nested
    @DisplayName("per-tenant canary (master switch false)")
    class Canary {

        private final PuzzleLayerPolicy policy =
                new PuzzleLayerPolicy(false, TENANT_A.toString());

        @Test
        @DisplayName("master switch stays false")
        void masterOff() {
            assertThat(policy.isGloballyEnabled()).isFalse();
        }

        @Test
        @DisplayName("the listed tenant is enabled, others are not")
        void onlyListedTenant() {
            assertThat(policy.isEnabledFor(TENANT_A)).isTrue();
            assertThat(policy.isEnabledFor(TENANT_B)).isFalse();
            assertThat(policy.isEnabledFor(null)).isFalse();
        }
    }

    @Test
    @DisplayName("canary list parsing tolerates whitespace, casing and an invalid token")
    void canaryListParsing() {
        PuzzleLayerPolicy policy = new PuzzleLayerPolicy(
                false, "  " + TENANT_A.toString().toUpperCase() + " , not-a-uuid , " + TENANT_B + " ");

        assertThat(policy.isEnabledFor(TENANT_A)).isTrue();
        assertThat(policy.isEnabledFor(TENANT_B)).isTrue();
        assertThat(policy.isGloballyEnabled()).isFalse();
    }
}
