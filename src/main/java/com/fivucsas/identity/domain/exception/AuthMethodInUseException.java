package com.fivucsas.identity.domain.exception;

import java.util.List;

/**
 * Thrown by the write-side no-lock-out guard when an admin tries to DISABLE a
 * login method that is still required by one or more of the tenant's ACTIVE
 * auth flows. Disabling it would create a state where the active flow demands a
 * method that login enforcement now blocks → users locked out.
 *
 * <p>Mapped to HTTP 409 Conflict with the stable error code
 * {@code AUTH_METHOD_IN_USE}, the method name, and the list of dependent active
 * flow names so the admin UI can name them ("SMS_OTP is used by 'Default 3-Step
 * Flow' — disable it there first, or override"). The admin may pass an explicit
 * {@code force=true} override to disable anyway (their choice, surfaced as a
 * warning).
 */
public class AuthMethodInUseException extends DomainException {

    private static final String ERROR_CODE = "AUTH_METHOD_IN_USE";

    private final String method;
    private final List<String> activeFlowNames;

    public AuthMethodInUseException(String method, List<String> activeFlowNames) {
        super("Auth method " + method + " is required by active auth flow(s): " + activeFlowNames,
                ERROR_CODE);
        this.method = method;
        this.activeFlowNames = activeFlowNames == null ? List.of() : List.copyOf(activeFlowNames);
    }

    public String getMethod() {
        return method;
    }

    public List<String> getActiveFlowNames() {
        return activeFlowNames;
    }
}
