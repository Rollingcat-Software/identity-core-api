package com.fivucsas.identity.domain.exception;

/**
 * Thrown at login time when a user tries to authenticate with a login method
 * that has been EXPLICITLY disabled for their tenant (an
 * {@code tenant_auth_methods} row with {@code is_enabled=false}).
 *
 * <p>Fail-closed for THAT method only: other enabled methods on the same step
 * still work. The block is per-(tenant, method); a method with no configuration
 * row is always allowed (see
 * {@link com.fivucsas.identity.application.service.TenantAuthMethodPolicy}).
 *
 * <p>Mapped by {@code GlobalExceptionHandler} to HTTP 403 Forbidden with the
 * stable error code {@code AUTH_METHOD_DISABLED} and the offending method name,
 * so the frontend can render a localized "this method is disabled — choose
 * another" message and steer the user to an enabled factor.
 */
public class AuthMethodDisabledException extends DomainException {

    private static final String ERROR_CODE = "AUTH_METHOD_DISABLED";

    private final String method;

    public AuthMethodDisabledException(String method) {
        super("Auth method " + method + " is disabled for this tenant", ERROR_CODE);
        this.method = method;
    }

    /** The {@code AuthMethodType} name that was rejected (e.g. "SMS_OTP"). */
    public String getMethod() {
        return method;
    }
}
