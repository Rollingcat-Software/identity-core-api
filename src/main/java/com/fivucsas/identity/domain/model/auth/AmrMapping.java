package com.fivucsas.identity.domain.model.auth;

import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Single source of truth for mapping an {@link AuthMethodType} to its RFC 8176
 * Authentication Method Reference ({@code amr}) value.
 *
 * <p>The {@code amr} claim in the issued tokens MUST be identical regardless of
 * which login path produced it (the single-step identifier-first mint in
 * {@code AuthenticateUserService} or the N-step MFA completion in
 * {@code VerifyMfaStepService}). Before this util existed, those two paths kept
 * private copies that diverged (notably {@code SMS_OTP} → {@code "otp"} vs
 * {@code "sms"}), so the same login could emit a different {@code amr} depending
 * on the route. Both paths now delegate here.</p>
 *
 * <p>Values are RFC 8176-registered where one applies
 * (<a href="https://www.iana.org/assignments/authentication-method-reference-values/">IANA registry</a>):
 * {@code pwd}, {@code otp}, {@code sms}, {@code hwk}, {@code swk}, {@code face},
 * {@code fpt}, {@code mca}. Methods with no registered value fall back to a
 * stable lower-cased enum name (e.g. {@code voice}, {@code puzzle}).</p>
 */
public final class AmrMapping {

    private static final Map<AuthMethodType, String> AMR_VALUES;

    static {
        Map<AuthMethodType, String> m = new EnumMap<>(AuthMethodType.class);
        m.put(AuthMethodType.PASSWORD, "pwd");
        // EMAIL_OTP and TOTP are generic one-time codes → RFC 8176 "otp".
        m.put(AuthMethodType.EMAIL_OTP, "otp");
        m.put(AuthMethodType.TOTP, "otp");
        // SMS_OTP is delivered over SMS → RFC 8176 has a dedicated "sms" value.
        m.put(AuthMethodType.SMS_OTP, "sms");
        m.put(AuthMethodType.FACE, "face");
        // VOICE has no RFC 8176-registered value → stable lower-cased fallback.
        m.put(AuthMethodType.VOICE, "voice");
        m.put(AuthMethodType.FINGERPRINT, "fpt");
        m.put(AuthMethodType.HARDWARE_KEY, "hwk");
        // PASSKEY is the discoverable mode of WebAuthn → same "hwk" amr.
        m.put(AuthMethodType.PASSKEY, "hwk");
        // QR_CODE and APPROVE_LOGIN are cross-device / multi-channel approvals →
        // RFC 8176 "mca" (multiple-channel authentication).
        m.put(AuthMethodType.QR_CODE, "mca");
        m.put(AuthMethodType.APPROVE_LOGIN, "mca");
        // NFC_DOCUMENT proves possession of a software/credential token → "swk".
        m.put(AuthMethodType.NFC_DOCUMENT, "swk");
        AMR_VALUES = Map.copyOf(m);
    }

    private AmrMapping() {
    }

    /**
     * Resolves the {@code amr} value for a single method. Methods without a
     * registered RFC 8176 value fall back to the lower-cased enum name (e.g.
     * {@code PUZZLE} → {@code "puzzle"}) so the claim is always stable and never
     * leaks an upper-cased enum constant.
     */
    public static String amrValue(AuthMethodType type) {
        String v = AMR_VALUES.get(type);
        return v != null ? v : type.name().toLowerCase(Locale.ROOT);
    }

    /**
     * Resolves the {@code amr} value for a method given by its enum NAME (the
     * form stored on an MFA session's completed-methods list). Unknown/garbage
     * names fall back to their own lower-cased form, mirroring the prior
     * {@code getOrDefault(..., name.toLowerCase())} behaviour so a malformed
     * session never throws at token-mint time.
     */
    public static String amrValue(String methodName) {
        try {
            return amrValue(AuthMethodType.valueOf(methodName));
        } catch (IllegalArgumentException | NullPointerException e) {
            return methodName == null ? null : methodName.toLowerCase(Locale.ROOT);
        }
    }

    /**
     * Maps a set of methods to their distinct {@code amr} values (e.g. EMAIL_OTP
     * + TOTP both collapse to a single {@code "otp"}).
     */
    public static List<String> amrFor(Set<AuthMethodType> methods) {
        return methods.stream()
                .map(AmrMapping::amrValue)
                .distinct()
                .toList();
    }
}
