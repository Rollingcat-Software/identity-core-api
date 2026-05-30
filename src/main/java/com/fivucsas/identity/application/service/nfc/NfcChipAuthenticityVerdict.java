package com.fivucsas.identity.application.service.nfc;

import java.util.Map;

/**
 * Fail-closed interpreter of the biometric-processor's NFC passive-authentication
 * (chip-authenticity) response.
 *
 * <p>The biometric-processor validates the eMRTD {@code EF.SOD} → Document
 * Signer → CSCA chain and the DG-hash binding, returning a JSON verdict. This
 * value object is the SINGLE place in the api that decides "is this chip
 * authentic?", so if agent-bio's field name ever changes only
 * {@link #AUTHORITATIVE_FIELD} (and the fallbacks) move.</p>
 *
 * <p>Frozen bio contract (agent-bio PR #131) — response (HTTP 200 even when not
 * authentic):</p>
 * <pre>
 * { "is_authentic": false,
 *   "reason": "DG2 hash mismatch",
 *   "reason_code": "DG_HASH_MISMATCH",   // OK | DG_HASH_MISMATCH | SIGNATURE_INVALID
 *                                        // | DS_UNTRUSTED | SOD_PARSE_ERROR
 *                                        // | NO_TRUST_STORE | MISSING_DG | UNSUPPORTED_ALGORITHM
 *   "ds_subject": "...", "ds_serial": "...",
 *   "csca_matched": false,
 *   "dg_hash_results": { "1": true, "2": false },
 *   "sod_hash_algorithm": "sha256" }
 * </pre>
 *
 * <p><b>Fail-closed contract:</b> a chip is authentic ONLY when the bio call
 * succeeded AND {@code is_authentic} is explicitly {@code true}. A transport
 * error, a {@code success=false} error map, a missing field, or a non-true value
 * all yield {@code authentic=false}. (Bio is itself fail-closed: an empty CSCA
 * trust store ⇒ {@code is_authentic=false, reason_code=NO_TRUST_STORE}.)</p>
 */
public final class NfcChipAuthenticityVerdict {

    /**
     * Authoritative verdict field name in the bio response — FROZEN contract
     * (agent-bio PR #131): {@code is_authentic}. Kept as a constant so a future
     * contract change is one edit.
     */
    static final String AUTHORITATIVE_FIELD = "is_authentic";

    /**
     * Accepted aliases for the authoritative verdict, in priority order. The
     * frozen field comes first; the rest are defense against contract drift.
     */
    private static final String[] AUTHORITATIVE_ALIASES = {
            AUTHORITATIVE_FIELD, "authentic", "passive_auth_passed", "valid"
    };

    private final boolean authentic;
    private final String reason;
    private final String reasonCode;

    private NfcChipAuthenticityVerdict(boolean authentic, String reason, String reasonCode) {
        this.authentic = authentic;
        this.reason = reason;
        this.reasonCode = reasonCode;
    }

    /**
     * Interprets a raw bio response map (or error map) fail-closed.
     *
     * @param bioResponse the map returned by
     *        {@code BiometricServicePort.verifyNfcChipAuthenticity}; may be a
     *        {@code {success=false, ...}} error map on transport failure, or even
     *        {@code null}
     */
    public static NfcChipAuthenticityVerdict from(Map<String, Object> bioResponse) {
        if (bioResponse == null) {
            return new NfcChipAuthenticityVerdict(false, "No response from biometric service", "NO_RESPONSE");
        }

        // Transport/availability failure surfaced by the adapter — fail-closed.
        if (Boolean.FALSE.equals(bioResponse.get("success"))) {
            Object msg = bioResponse.getOrDefault("message", bioResponse.get("error"));
            return new NfcChipAuthenticityVerdict(false,
                    msg != null ? String.valueOf(msg) : "Biometric service error",
                    "SERVICE_ERROR");
        }

        Boolean verdict = firstBoolean(bioResponse, AUTHORITATIVE_ALIASES);
        if (verdict == null) {
            // Bio responded but without a recognizable verdict field — treat as
            // not authentic rather than silently passing.
            return new NfcChipAuthenticityVerdict(false,
                    "Biometric service returned no authenticity verdict", "NO_VERDICT");
        }

        String reason = stringOrNull(bioResponse.get("reason"));
        String reasonCode = stringOrNull(bioResponse.get("reason_code"));
        if (Boolean.TRUE.equals(verdict)) {
            return new NfcChipAuthenticityVerdict(true, reason, reasonCode != null ? reasonCode : "OK");
        }
        return new NfcChipAuthenticityVerdict(false,
                reason != null ? reason : "Chip passive authentication failed",
                reasonCode);
    }

    /** @return true only if the chip is positively verified authentic. */
    public boolean isAuthentic() {
        return authentic;
    }

    /** @return a human-readable failure/diagnostic reason (may be null on success). */
    public String reason() {
        return reason;
    }

    /**
     * @return the stable {@code reason_code} enum from bio (OK, DG_HASH_MISMATCH,
     *         SIGNATURE_INVALID, DS_UNTRUSTED, SOD_PARSE_ERROR, NO_TRUST_STORE,
     *         MISSING_DG, UNSUPPORTED_ALGORITHM) or an api-side synthetic code
     *         (NO_RESPONSE, SERVICE_ERROR, NO_VERDICT). May be null.
     */
    public String reasonCode() {
        return reasonCode;
    }

    private static Boolean firstBoolean(Map<String, Object> map, String[] keys) {
        for (String key : keys) {
            Object v = map.get(key);
            if (v instanceof Boolean b) {
                return b;
            }
            if (v instanceof String s) {
                if ("true".equalsIgnoreCase(s.trim())) {
                    return Boolean.TRUE;
                }
                if ("false".equalsIgnoreCase(s.trim())) {
                    return Boolean.FALSE;
                }
            }
        }
        return null;
    }

    private static String stringOrNull(Object o) {
        if (o == null) {
            return null;
        }
        String s = String.valueOf(o).trim();
        return s.isEmpty() ? null : s;
    }
}
