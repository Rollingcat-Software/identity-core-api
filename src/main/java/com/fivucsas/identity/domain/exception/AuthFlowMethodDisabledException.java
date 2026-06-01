package com.fivucsas.identity.domain.exception;

import java.util.List;

/**
 * Thrown by the auth-flow builder's no-lock-out guard when a flow being
 * created / activated / made-default references a login method that is
 * EXPLICITLY disabled for the tenant. Saving it would let login enforcement
 * block a method the active flow demands → users stranded mid-flow.
 *
 * <p>Mapped to HTTP 422 Unprocessable Entity with the stable error code
 * {@code AUTH_FLOW_METHOD_DISABLED} and the list of disabled method names, so
 * the admin UI can say "TOTP is disabled for this tenant — re-enable it or
 * remove it from the flow".
 */
public class AuthFlowMethodDisabledException extends DomainException {

    private static final String ERROR_CODE = "AUTH_FLOW_METHOD_DISABLED";

    private final List<String> disabledMethods;

    public AuthFlowMethodDisabledException(List<String> disabledMethods) {
        super("Auth flow references method(s) disabled for this tenant: " + disabledMethods,
                ERROR_CODE);
        this.disabledMethods = disabledMethods == null ? List.of() : List.copyOf(disabledMethods);
    }

    public List<String> getDisabledMethods() {
        return disabledMethods;
    }
}
