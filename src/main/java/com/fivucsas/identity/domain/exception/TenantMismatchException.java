package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a user attempts to authenticate via a tenant-bound OAuth client
 * (hosted login surface) but the user's home tenant does not match the
 * client's tenant.
 *
 * <p>Example scenario: a {@code @gmail.com} user submits the password form on
 * Marmara University's hosted login page ({@code demo.fivucsas.com} →
 * {@code marmara-bys-demo} client). The user belongs to the Fivucsas system
 * tenant, the client is bound to Marmara — the password must be rejected
 * <em>before</em> it is checked, so the user does not pass through to MFA
 * (where they would fail again because they have no enrollments in Marmara's
 * tenant) and so we never leak whether the password matched.
 *
 * <p>Carries the human-readable {@code requiredTenant} name so the frontend
 * can render a localized inline error such as "This account is not a Marmara
 * member."
 *
 * <p>Mapped by {@link com.fivucsas.identity.exception.GlobalExceptionHandler}
 * to HTTP 403 Forbidden with body shape:
 * <pre>
 * {
 *   "errorCode": "TENANT_MISMATCH",
 *   "message": "Account does not belong to the requested tenant",
 *   "requiredTenant": "Marmara University",
 *   "path": "/api/v1/auth/login"
 * }
 * </pre>
 */
public class TenantMismatchException extends DomainException {

    private static final String DEFAULT_MESSAGE =
            "Account does not belong to the requested tenant";
    private static final String ERROR_CODE = "TENANT_MISMATCH";

    private final String requiredTenant;

    public TenantMismatchException(String requiredTenant) {
        super(DEFAULT_MESSAGE, ERROR_CODE);
        this.requiredTenant = requiredTenant;
    }

    public TenantMismatchException(String message, String requiredTenant) {
        super(message, ERROR_CODE);
        this.requiredTenant = requiredTenant;
    }

    /**
     * Human-readable name of the tenant the requesting OAuth client is bound
     * to (e.g. "Marmara University"). May fall back to the OAuth
     * {@code client_id} when no friendly tenant name is available.
     */
    public String getRequiredTenant() {
        return requiredTenant;
    }
}
