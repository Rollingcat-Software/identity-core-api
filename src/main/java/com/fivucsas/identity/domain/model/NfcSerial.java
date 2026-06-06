package com.fivucsas.identity.domain.model;

import java.util.Locale;

/**
 * Canonical NFC card serial normalization at the API ingest boundary.
 *
 * <p><b>The cross-client problem.</b> Different FIVUCSAS clients hand us the
 * same physical card serial in different textual shapes:</p>
 * <ul>
 *   <li><b>Web</b> (Web NFC {@code NDEFReadingEvent.serialNumber}) →
 *       lowercase hex with colon separators, e.g. {@code "04:a2:24:5b:6f:71:80"}.</li>
 *   <li><b>Mobile</b> (Android {@code Tag.getId()} / iOS CoreNFC) →
 *       upper-case hex, contiguous, e.g. {@code "04A2245B6F7180"}.</li>
 * </ul>
 *
 * <p>If the same card is enrolled from mobile (UPPERHEX) and then verified
 * from web (lowercase:colons) — or vice-versa — a naive string equality
 * lookup misses and the user is wrongly told the card is "not enrolled".</p>
 *
 * <p><b>Canonical form.</b> We normalize EVERY serial on the way in to
 * <b>upper-case hex with no separators</b> (e.g. {@code "04A2245B6F7180"}) and
 * store/look-up that. Mobile UPPERHEX is already canonical; web's lowercase
 * colon form maps onto it losslessly. The normalization is:</p>
 * <ol>
 *   <li>strip the common separators {@code : - . space};</li>
 *   <li>upper-case;</li>
 *   <li>if (and only if) the stripped value is pure hex, keep the stripped
 *       hex as the canonical serial.</li>
 * </ol>
 *
 * <p>Non-hex serials (some proprietary cards expose an opaque alphanumeric id)
 * are NOT hex, so we fall back to a conservative normalization — upper-case +
 * trim — without stripping separators, preserving the original token while
 * still making the comparison case-insensitive. This keeps the change safe for
 * any already-enrolled non-hex serial.</p>
 *
 * <p>This is a pure function with no Spring/JPA dependencies so it can run from
 * both the application service (enroll/verify) and the MFA auth handler.</p>
 */
public final class NfcSerial {

    private NfcSerial() {
        // static utility
    }

    /**
     * Normalizes a raw client-supplied NFC serial to its canonical form
     * (UPPERHEX, no separators, for hex serials).
     *
     * @param raw the serial exactly as a client sent it (web colon form,
     *            mobile UPPERHEX, or an opaque alphanumeric id)
     * @return the canonical serial, or {@code null}/blank passed through
     *         unchanged so callers keep their existing null handling
     */
    public static String canonicalize(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) {
            return trimmed;
        }

        // Strip the separators web/mobile readers interleave into hex serials.
        String stripped = trimmed.replaceAll("[:\\-.\\s]", "");

        if (isHex(stripped)) {
            // Canonical: contiguous UPPERHEX. Mobile already matches this;
            // web's "04:a2:..:" collapses onto it. Locale.ROOT — a bare
            // toUpperCase() under tr_TR maps 'i'→'İ' / 'I'→'ı', corrupting
            // serials (e.g. "SERIAL-2" → "SERİAL-2") and breaking lookups.
            return stripped.toUpperCase(Locale.ROOT);
        }

        // Opaque / non-hex serial — don't mangle it by stripping characters
        // that may be significant. Upper-case + trim keeps comparison
        // case-insensitive while preserving the token verbatim. Locale.ROOT for
        // the same Turkish 'i'/'I' reason as the hex branch above.
        return trimmed.toUpperCase(Locale.ROOT);
    }

    private static boolean isHex(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }
}
