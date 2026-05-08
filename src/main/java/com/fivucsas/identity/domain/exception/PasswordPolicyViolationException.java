package com.fivucsas.identity.domain.exception;

import java.util.Collections;
import java.util.List;

/**
 * Thrown by {@link com.fivucsas.identity.domain.model.user.PasswordPolicy}
 * when a candidate password fails one or more rules.
 *
 * <p>Carries a stable {@code PASSWORD_POLICY_VIOLATION} error code and a
 * machine-readable list of violation keys (e.g.
 * {@code MIN_LENGTH}, {@code REQUIRE_UPPERCASE}). The frontend renders
 * the user-facing copy via i18n keys keyed off these tokens —
 * {@code errors.password.MIN_LENGTH}, etc. — instead of receiving
 * concatenated English strings (the legacy shape blew through Turkish
 * locales because the policy returned hardcoded English).
 *
 * <p>INVESTIGATION_MASTER_2026-05-07 §"user constraints":
 * "Password-policy errors return concatenated English from
 * PasswordPolicy.java:69".
 */
public class PasswordPolicyViolationException extends DomainException {

    private static final String ERROR_CODE = "PASSWORD_POLICY_VIOLATION";

    private final List<String> violationKeys;

    public PasswordPolicyViolationException(List<String> violationKeys) {
        super("Password does not meet policy requirements", ERROR_CODE);
        this.violationKeys = violationKeys != null
                ? List.copyOf(violationKeys)
                : Collections.emptyList();
    }

    /**
     * Stable, locale-independent identifiers for each rule the candidate
     * failed. The frontend looks these up in en.json / tr.json under
     * {@code errors.password.<key>}. Order is preserved so the UI can show
     * violations in the same order the validator emits them.
     */
    public List<String> getViolationKeys() {
        return violationKeys;
    }
}
