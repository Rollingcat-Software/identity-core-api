package com.fivucsas.identity.domain.exception;

/**
 * Thrown when an OTP code has been guessed incorrectly too many times.
 *
 * <p>The OTP store enforces a per-code attempt counter (NIST 800-63B
 * §5.1.1.2 / §5.2.2): once the user has burned through {@code MAX_ATTEMPTS}
 * mismatches against the same issued code, the code is invalidated server-side
 * regardless of its remaining TTL. This caps the online-guessing attack
 * window per code at the chosen attempt budget rather than at
 * {@code TTL × per-IP-rate-limit}.</p>
 */
public class OtpAttemptsExhaustedException extends DomainException {

    private static final String DEFAULT_MESSAGE =
            "Too many invalid attempts. Please request a new OTP code.";
    private static final String ERROR_CODE = "OTP_ATTEMPTS_EXHAUSTED";

    public OtpAttemptsExhaustedException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public OtpAttemptsExhaustedException(String message) {
        super(message, ERROR_CODE);
    }
}
