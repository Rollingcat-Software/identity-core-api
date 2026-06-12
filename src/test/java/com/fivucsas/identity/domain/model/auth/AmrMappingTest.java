package com.fivucsas.identity.domain.model.auth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the single source of truth for the RFC 8176 {@code amr} mapping and the
 * invariant that BOTH login paths (single-step identifier-first mint and the
 * N-step MFA completion) resolve the same {@code amr} for a given method.
 */
@DisplayName("AmrMapping — shared RFC 8176 amr resolution")
class AmrMappingTest {

    @Test
    @DisplayName("SMS_OTP resolves to the RFC 8176 'sms' value (was divergent: 'otp' vs 'sms')")
    void smsOtpResolvesToSms() {
        assertThat(AmrMapping.amrValue(AuthMethodType.SMS_OTP)).isEqualTo("sms");
        assertThat(AmrMapping.amrValue("SMS_OTP")).isEqualTo("sms");
    }

    @Test
    @DisplayName("Registered RFC 8176 values for every login factor")
    void registeredValues() {
        assertThat(AmrMapping.amrValue(AuthMethodType.PASSWORD)).isEqualTo("pwd");
        assertThat(AmrMapping.amrValue(AuthMethodType.EMAIL_OTP)).isEqualTo("otp");
        assertThat(AmrMapping.amrValue(AuthMethodType.TOTP)).isEqualTo("otp");
        assertThat(AmrMapping.amrValue(AuthMethodType.SMS_OTP)).isEqualTo("sms");
        assertThat(AmrMapping.amrValue(AuthMethodType.FACE)).isEqualTo("face");
        assertThat(AmrMapping.amrValue(AuthMethodType.VOICE)).isEqualTo("voice");
        assertThat(AmrMapping.amrValue(AuthMethodType.FINGERPRINT)).isEqualTo("fpt");
        assertThat(AmrMapping.amrValue(AuthMethodType.HARDWARE_KEY)).isEqualTo("hwk");
        assertThat(AmrMapping.amrValue(AuthMethodType.PASSKEY)).isEqualTo("hwk");
        assertThat(AmrMapping.amrValue(AuthMethodType.QR_CODE)).isEqualTo("mca");
        assertThat(AmrMapping.amrValue(AuthMethodType.APPROVE_LOGIN)).isEqualTo("mca");
        assertThat(AmrMapping.amrValue(AuthMethodType.NFC_DOCUMENT)).isEqualTo("swk");
    }

    @ParameterizedTest
    @EnumSource(AuthMethodType.class)
    @DisplayName("The enum-typed and the String-name resolvers AGREE for every method "
            + "— so the single-step and MFA paths can never diverge")
    void bothPathsAgreeForEveryMethod(AuthMethodType type) {
        // AuthenticateUserService (single-step) resolves by enum;
        // VerifyMfaStepService (MFA) resolves by the completed-method enum NAME.
        String byEnum = AmrMapping.amrValue(type);
        String byName = AmrMapping.amrValue(type.name());
        assertThat(byEnum)
                .as("amr for %s must be identical whether resolved by enum or by name", type)
                .isEqualTo(byName);
    }

    @Test
    @DisplayName("Methods with no registered value fall back to a stable lower-cased name")
    void unmappedFallsBackToLowercaseName() {
        // PUZZLE is a login factor but has no RFC 8176-registered value.
        assertThat(AmrMapping.amrValue(AuthMethodType.PUZZLE)).isEqualTo("puzzle");
        // Garbage/unknown completed-method name never throws.
        assertThat(AmrMapping.amrValue("NOT_A_METHOD")).isEqualTo("not_a_method");
    }

    @Test
    @DisplayName("amrFor collapses methods that share a value to a single distinct entry")
    void amrForCollapsesDuplicates() {
        // EMAIL_OTP + TOTP both → "otp" → one entry.
        assertThat(AmrMapping.amrFor(Set.of(AuthMethodType.EMAIL_OTP, AuthMethodType.TOTP)))
                .containsExactly("otp");
        assertThat(AmrMapping.amrFor(Set.of(AuthMethodType.PASSWORD)))
                .containsExactly("pwd");
    }

    @Test
    @DisplayName("Null name is tolerated (returns null), matching prior getOrDefault leniency")
    void nullNameTolerated() {
        assertThat(AmrMapping.amrValue((String) null)).isNull();
    }
}
