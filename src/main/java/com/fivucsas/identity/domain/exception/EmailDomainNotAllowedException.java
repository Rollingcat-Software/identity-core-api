package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a tenant has {@code enforce_domain_matching=true} and a
 * registrant's email domain is NOT present in that tenant's
 * {@code tenant_email_domains} registry (V44).
 *
 * <p>This is the opt-in enforcement counterpart to the graceful default
 * behaviour: when enforcement is OFF, an unmatched domain simply falls through
 * to the default tenant; when enforcement is ON for the resolved/targeted
 * tenant, registration is rejected outright.</p>
 *
 * <p>Fired by
 * {@link com.fivucsas.identity.application.service.RegisterUserService} BEFORE
 * the {@code users.save()} call (and before bcrypt-hashing the password), so
 * the gate is enforced server-side regardless of caller surface.</p>
 *
 * <p>Mapped by {@link com.fivucsas.identity.exception.GlobalExceptionHandler}
 * to HTTP 422 Unprocessable Entity with body shape:
 * <pre>
 * {
 *   "errorCode": "EMAIL_DOMAIN_NOT_ALLOWED",
 *   "message": "Email domain 'gmail.com' is not allowed to register with this organisation",
 *   "emailDomain": "gmail.com",
 *   "path": "/api/v1/auth/register"
 * }
 * </pre>
 *
 * <p>We use 422 (not 403): the caller IS authenticated/permitted to hit the
 * registration endpoint, but the submitted email-domain is semantically
 * unacceptable for the target tenant — a request-content problem, which 422
 * models more precisely than 403.</p>
 */
public class EmailDomainNotAllowedException extends DomainException {

    private static final String ERROR_CODE = "EMAIL_DOMAIN_NOT_ALLOWED";

    private final String emailDomain;

    public EmailDomainNotAllowedException(String emailDomain) {
        super("Email domain '" + emailDomain + "' is not allowed to register "
                + "with this organisation", ERROR_CODE);
        this.emailDomain = emailDomain;
    }

    public String getEmailDomain() {
        return emailDomain;
    }
}
