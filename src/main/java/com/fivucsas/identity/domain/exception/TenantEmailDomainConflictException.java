package com.fivucsas.identity.domain.exception;

/**
 * Thrown for state conflicts while managing a tenant's email-domain registry
 * (V44 {@code tenant_email_domains}) via the admin CRUD API.
 *
 * <p>Two concrete cases, distinguished by {@code errorCode}:</p>
 * <ul>
 *   <li>{@code EMAIL_DOMAIN_ALREADY_CLAIMED} — the domain is already owned by
 *       ANOTHER tenant. The unique index {@code ux_tenant_email_domains_domain}
 *       guarantees a domain maps to at most one tenant; we pre-check and throw a
 *       clean 409 rather than leaking the raw DB constraint violation as a
 *       500.</li>
 *   <li>{@code CANNOT_REMOVE_LAST_DOMAIN} — removing this row would leave the
 *       tenant with zero domains while {@code enforce_domain_matching=true},
 *       which would lock out ALL future signups. Refused with 409.</li>
 * </ul>
 *
 * <p>Mapped by {@link com.fivucsas.identity.exception.GlobalExceptionHandler}
 * to HTTP 409 Conflict.</p>
 */
public class TenantEmailDomainConflictException extends DomainException {

    public static final String ALREADY_CLAIMED = "EMAIL_DOMAIN_ALREADY_CLAIMED";
    public static final String LAST_DOMAIN = "CANNOT_REMOVE_LAST_DOMAIN";

    private TenantEmailDomainConflictException(String message, String errorCode) {
        super(message, errorCode);
    }

    /** The domain is already owned by another tenant. */
    public static TenantEmailDomainConflictException alreadyClaimed(String domain) {
        return new TenantEmailDomainConflictException(
                "Email domain '" + domain + "' is already claimed by another tenant",
                ALREADY_CLAIMED);
    }

    /**
     * Refused: this is the tenant's last domain and enforcement is on, so
     * removing it would lock out every future signup.
     */
    public static TenantEmailDomainConflictException lastDomain(String domain) {
        return new TenantEmailDomainConflictException(
                "Cannot remove the last email domain '" + domain + "' while domain "
                        + "enforcement is enabled — this would lock out all new signups. "
                        + "Disable enforcement or add another domain first.",
                LAST_DOMAIN);
    }
}
