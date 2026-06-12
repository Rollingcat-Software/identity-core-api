package com.fivucsas.identity.application.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ClientSideEmbeddingPolicy} — the kill-switch that gates
 * the client-side-embedding face path (sub-project A, Phase 5).
 *
 * <p>Mirrors {@link ConfigDrivenLoginPolicyTest} in structure: proves the
 * default-OFF behaviour (legacy image path unchanged for every tenant), the
 * global master-switch ON behaviour, and the per-tenant canary list.</p>
 */
@DisplayName("ClientSideEmbeddingPolicy")
class ClientSideEmbeddingPolicyTest {

    private static final UUID TENANT_A = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID TENANT_B = UUID.fromString("22222222-2222-2222-2222-222222222222");

    @Nested
    @DisplayName("default OFF (flag false, no canary)")
    class DefaultOff {

        private final ClientSideEmbeddingPolicy policy =
                new ClientSideEmbeddingPolicy(false, "");

        @Test
        @DisplayName("isEnabled() is false")
        void globalOff() {
            assertThat(policy.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("isEnabledForTenant() is false for any tenant")
        void perTenantOff() {
            assertThat(policy.isEnabledForTenant(TENANT_A)).isFalse();
            assertThat(policy.isEnabledForTenant(TENANT_B)).isFalse();
            assertThat(policy.isEnabledForTenant((UUID) null)).isFalse();
        }
    }

    @Nested
    @DisplayName("global ON (master switch true)")
    class GlobalOn {

        private final ClientSideEmbeddingPolicy policy =
                new ClientSideEmbeddingPolicy(true, "");

        @Test
        @DisplayName("isEnabled() is true")
        void globalOn() {
            assertThat(policy.isEnabled()).isTrue();
        }

        @Test
        @DisplayName("isEnabledForTenant() is true for every tenant")
        void perTenantOn() {
            assertThat(policy.isEnabledForTenant(TENANT_A)).isTrue();
            assertThat(policy.isEnabledForTenant(TENANT_B)).isTrue();
        }
    }

    @Nested
    @DisplayName("per-tenant canary (master switch false)")
    class Canary {

        private final ClientSideEmbeddingPolicy policy =
                new ClientSideEmbeddingPolicy(false, TENANT_A.toString());

        @Test
        @DisplayName("master switch stays false")
        void masterOff() {
            assertThat(policy.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("the listed tenant is enabled, others are not")
        void onlyListedTenant() {
            assertThat(policy.isEnabledForTenant(TENANT_A)).isTrue();
            assertThat(policy.isEnabledForTenant(TENANT_B)).isFalse();
            assertThat(policy.isEnabledForTenant((UUID) null)).isFalse();
        }
    }

    @Test
    @DisplayName("canary list parsing tolerates whitespace, casing and an invalid token")
    void canaryListParsing() {
        ClientSideEmbeddingPolicy policy = new ClientSideEmbeddingPolicy(
                false, "  " + TENANT_A.toString().toUpperCase() + " , not-a-uuid , " + TENANT_B + " ");

        assertThat(policy.isEnabledForTenant(TENANT_A)).isTrue();
        assertThat(policy.isEnabledForTenant(TENANT_B)).isTrue();
        assertThat(policy.isEnabled()).isFalse();
    }

    /**
     * The String overload is the single source of truth for the enroll routing
     * gate ({@code EnrollBiometricService} routing + the controller's fail-closed
     * reject both delegate here). A null / blank / non-UUID tenant id must be
     * enabled ONLY under the global switch, NEVER via the canary list — a
     * malformed id cannot match a canary entry and must not silently widen the
     * rollout.
     */
    @Nested
    @DisplayName("String-tenant overload (enroll/verify command shape)")
    class StringOverload {

        @Test
        @DisplayName("global ON → true for any String (valid UUID, blank, or non-UUID)")
        void globalOnEnablesEverything() {
            ClientSideEmbeddingPolicy policy = new ClientSideEmbeddingPolicy(true, "");
            assertThat(policy.isEnabledForTenant(TENANT_A.toString())).isTrue();
            assertThat(policy.isEnabledForTenant((String) null)).isTrue();
            assertThat(policy.isEnabledForTenant("")).isTrue();
            assertThat(policy.isEnabledForTenant("not-a-uuid")).isTrue();
        }

        @Test
        @DisplayName("canary (master OFF) → only the listed UUID String, never null/blank/non-UUID")
        void canaryOnlyForListedUuidString() {
            ClientSideEmbeddingPolicy policy =
                    new ClientSideEmbeddingPolicy(false, TENANT_A.toString());
            assertThat(policy.isEnabledForTenant(TENANT_A.toString())).isTrue();
            // Whitespace + casing tolerated (UUID.fromString is case-insensitive).
            assertThat(policy.isEnabledForTenant("  " + TENANT_A.toString().toUpperCase() + " ")).isTrue();
            assertThat(policy.isEnabledForTenant(TENANT_B.toString())).isFalse();
            assertThat(policy.isEnabledForTenant((String) null)).isFalse();
            assertThat(policy.isEnabledForTenant("")).isFalse();
            assertThat(policy.isEnabledForTenant("not-a-uuid")).isFalse();
        }

        @Test
        @DisplayName("default OFF → false for any String")
        void defaultOffEverythingFalse() {
            ClientSideEmbeddingPolicy policy = new ClientSideEmbeddingPolicy(false, "");
            assertThat(policy.isEnabledForTenant(TENANT_A.toString())).isFalse();
            assertThat(policy.isEnabledForTenant((String) null)).isFalse();
        }
    }
}
