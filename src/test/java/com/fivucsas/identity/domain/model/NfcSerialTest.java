package com.fivucsas.identity.domain.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("NfcSerial canonicalization (web ↔ mobile serial alignment)")
class NfcSerialTest {

    @Test
    @DisplayName("web lowercase:colons and mobile UPPERHEX collapse to the SAME canonical serial")
    void webAndMobileFormsMatch() {
        String web = "04:a2:24:5b:6f:71:80";   // Web NFC NDEFReadingEvent.serialNumber
        String mobile = "04A2245B6F7180";        // Android Tag.getId() / iOS CoreNFC

        String canonicalWeb = NfcSerial.canonicalize(web);
        String canonicalMobile = NfcSerial.canonicalize(mobile);

        assertThat(canonicalWeb).isEqualTo("04A2245B6F7180");
        assertThat(canonicalMobile).isEqualTo("04A2245B6F7180");
        assertThat(canonicalWeb).isEqualTo(canonicalMobile);
    }

    @ParameterizedTest
    @CsvSource({
            "'04:a2:24:5b:6f:71:80', 04A2245B6F7180",
            "'04-a2-24-5b',          04A2245B",
            "'04 a2 24 5b',          04A2245B",
            "'04.a2.24.5b',          04A2245B",
            "'04a2245b6f7180',       04A2245B6F7180",
            "'04A2245B6F7180',       04A2245B6F7180",
            "'  04a2245b  ',         04A2245B"
    })
    @DisplayName("hex serials strip separators and upper-case to canonical UPPERHEX")
    void hexSerialsCanonicalize(String raw, String expected) {
        assertThat(NfcSerial.canonicalize(raw)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"SERIAL-2", "serial-2", "ABC123XYZ", "card_007"})
    @DisplayName("non-hex / opaque serials are upper-cased + trimmed but NOT separator-stripped")
    void nonHexSerialsPreserveSeparators() {
        // 'SERIAL-2' contains S/R/I/L which are not hex digits → opaque path.
        assertThat(NfcSerial.canonicalize("SERIAL-2")).isEqualTo("SERIAL-2");
        assertThat(NfcSerial.canonicalize("serial-2")).isEqualTo("SERIAL-2");
        assertThat(NfcSerial.canonicalize("ABC123XYZ")).isEqualTo("ABC123XYZ");
        assertThat(NfcSerial.canonicalize("  card_007 ")).isEqualTo("CARD_007");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("null/blank pass through unchanged (callers keep their null handling)")
    void nullAndBlankPassThrough(String input) {
        assertThat(NfcSerial.canonicalize(input)).isEqualTo(input);
    }

    @Test
    @DisplayName("whitespace-only canonicalizes to empty after trim")
    void whitespaceOnlyTrimsToEmpty() {
        assertThat(NfcSerial.canonicalize("   ")).isEmpty();
    }
}
