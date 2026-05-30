package com.fivucsas.identity.application.service.nfc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("NfcChipAuthenticityVerdict — fail-closed interpretation of the bio passive-auth response")
class NfcChipAuthenticityVerdictTest {

    @Test
    @DisplayName("frozen contract is_authentic=true → authentic, reasonCode OK")
    void isAuthenticTrue() {
        var v = NfcChipAuthenticityVerdict.from(Map.of(
                "is_authentic", true, "reason", "ok", "reason_code", "OK"));
        assertThat(v.isAuthentic()).isTrue();
        assertThat(v.reason()).isEqualTo("ok");
        assertThat(v.reasonCode()).isEqualTo("OK");
    }

    @Test
    @DisplayName("is_authentic=false → not authentic, carries reason + reason_code")
    void isAuthenticFalse() {
        var v = NfcChipAuthenticityVerdict.from(Map.of(
                "is_authentic", false, "reason", "DG2 hash mismatch", "reason_code", "DG_HASH_MISMATCH"));
        assertThat(v.isAuthentic()).isFalse();
        assertThat(v.reason()).isEqualTo("DG2 hash mismatch");
        assertThat(v.reasonCode()).isEqualTo("DG_HASH_MISMATCH");
    }

    @Test
    @DisplayName("empty CSCA store (NO_TRUST_STORE, is_authentic=false) → fail-closed")
    void noTrustStoreFailsClosed() {
        var v = NfcChipAuthenticityVerdict.from(Map.of(
                "is_authentic", false, "reason_code", "NO_TRUST_STORE", "csca_matched", false));
        assertThat(v.isAuthentic()).isFalse();
        assertThat(v.reasonCode()).isEqualTo("NO_TRUST_STORE");
    }

    @Test
    @DisplayName("transport error map (success=false) → fail-closed not authentic")
    void transportErrorFailsClosed() {
        var v = NfcChipAuthenticityVerdict.from(Map.of(
                "success", false, "message", "NFC authenticity service unavailable"));
        assertThat(v.isAuthentic()).isFalse();
        assertThat(v.reason()).contains("unavailable");
        assertThat(v.reasonCode()).isEqualTo("SERVICE_ERROR");
    }

    @Test
    @DisplayName("null response → fail-closed not authentic")
    void nullResponseFailsClosed() {
        var v = NfcChipAuthenticityVerdict.from(null);
        assertThat(v.isAuthentic()).isFalse();
        assertThat(v.reasonCode()).isEqualTo("NO_RESPONSE");
    }

    @Test
    @DisplayName("missing verdict field → fail-closed not authentic (no silent pass)")
    void missingVerdictFailsClosed() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("csca_matched", true);   // looks positive but no authoritative field
        var v = NfcChipAuthenticityVerdict.from(resp);
        assertThat(v.isAuthentic()).isFalse();
        assertThat(v.reasonCode()).isEqualTo("NO_VERDICT");
    }

    @Test
    @DisplayName("legacy alias 'authentic' is still honoured (contract-drift defense)")
    void aliasFieldHonoured() {
        var v = NfcChipAuthenticityVerdict.from(Map.of("authentic", true));
        assertThat(v.isAuthentic()).isTrue();
    }

    @Test
    @DisplayName("string 'true'/'false' verdict values are parsed")
    void stringBooleanValues() {
        assertThat(NfcChipAuthenticityVerdict.from(Map.of("is_authentic", "true")).isAuthentic()).isTrue();
        assertThat(NfcChipAuthenticityVerdict.from(Map.of("is_authentic", "false")).isAuthentic()).isFalse();
    }
}
