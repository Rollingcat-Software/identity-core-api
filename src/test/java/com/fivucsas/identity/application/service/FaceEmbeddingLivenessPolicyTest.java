package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.service.FaceEmbeddingLivenessPolicy.Mode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("FaceEmbeddingLivenessPolicy — mode parsing and per-tenant ENFORCE canary")
class FaceEmbeddingLivenessPolicyTest {

    private static final UUID TENANT_A = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");
    private static final UUID TENANT_B = UUID.fromString("bbbbbbbb-0000-0000-0000-000000000002");

    @Test
    @DisplayName("each mode value parses (case and whitespace tolerant)")
    void parsesEveryMode() {
        assertThat(new FaceEmbeddingLivenessPolicy("OFF", "").globalMode()).isEqualTo(Mode.OFF);
        assertThat(new FaceEmbeddingLivenessPolicy("audit", "").globalMode()).isEqualTo(Mode.AUDIT);
        assertThat(new FaceEmbeddingLivenessPolicy(" Enforce ", "").globalMode()).isEqualTo(Mode.ENFORCE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "  ", "ON", "true", "STRICT", "enforced"})
    @DisplayName("an unknown or blank value becomes AUDIT, never ENFORCE")
    void unknownValueBecomesAudit(String raw) {
        assertThat(new FaceEmbeddingLivenessPolicy(raw, "").globalMode()).isEqualTo(Mode.AUDIT);
    }

    @Test
    @DisplayName("a null value becomes AUDIT")
    void nullValueBecomesAudit() {
        assertThat(new FaceEmbeddingLivenessPolicy(null, null).globalMode()).isEqualTo(Mode.AUDIT);
    }

    @Test
    @DisplayName("AUDIT + canary list: listed tenant gets ENFORCE, others AUDIT")
    void canaryTenantGetsEnforceUnderAudit() {
        FaceEmbeddingLivenessPolicy policy =
                new FaceEmbeddingLivenessPolicy("AUDIT", TENANT_A.toString().toUpperCase(java.util.Locale.ROOT));

        assertThat(policy.modeFor(TENANT_A)).isEqualTo(Mode.ENFORCE);
        assertThat(policy.modeFor(TENANT_B)).isEqualTo(Mode.AUDIT);
        assertThat(policy.modeFor((UUID) null)).isEqualTo(Mode.AUDIT);
    }

    @Test
    @DisplayName("OFF is the full kill-switch: the canary list cannot turn ENFORCE on")
    void offIgnoresCanaryList() {
        FaceEmbeddingLivenessPolicy policy = new FaceEmbeddingLivenessPolicy("OFF", TENANT_A.toString());

        assertThat(policy.modeFor(TENANT_A)).isEqualTo(Mode.OFF);
        assertThat(policy.modeFor(TENANT_A.toString())).isEqualTo(Mode.OFF);
    }

    @Test
    @DisplayName("global ENFORCE applies to every tenant, listed or not, and to a null tenant")
    void globalEnforceAppliesEverywhere() {
        FaceEmbeddingLivenessPolicy policy = new FaceEmbeddingLivenessPolicy("ENFORCE", "");

        assertThat(policy.modeFor(TENANT_B)).isEqualTo(Mode.ENFORCE);
        assertThat(policy.modeFor((UUID) null)).isEqualTo(Mode.ENFORCE);
        assertThat(policy.modeFor((String) null)).isEqualTo(Mode.ENFORCE);
    }

    @Test
    @DisplayName("invalid canary tokens are skipped; valid ones still apply")
    void invalidCanaryTokensSkipped() {
        FaceEmbeddingLivenessPolicy policy = new FaceEmbeddingLivenessPolicy(
                "AUDIT", "not-a-uuid, ," + TENANT_B + " ,zzz");

        assertThat(policy.modeFor(TENANT_B)).isEqualTo(Mode.ENFORCE);
        assertThat(policy.modeFor(TENANT_A)).isEqualTo(Mode.AUDIT);
    }

    @Test
    @DisplayName("String overload: UUID string matches the canary; null, blank or non-UUID gets the global mode")
    void stringOverload() {
        FaceEmbeddingLivenessPolicy policy = new FaceEmbeddingLivenessPolicy("AUDIT", TENANT_A.toString());

        assertThat(policy.modeFor(" " + TENANT_A + " ")).isEqualTo(Mode.ENFORCE);
        assertThat(policy.modeFor(TENANT_B.toString())).isEqualTo(Mode.AUDIT);
        assertThat(policy.modeFor((String) null)).isEqualTo(Mode.AUDIT);
        assertThat(policy.modeFor("  ")).isEqualTo(Mode.AUDIT);
        assertThat(policy.modeFor("t-marmara")).isEqualTo(Mode.AUDIT);
    }
}
