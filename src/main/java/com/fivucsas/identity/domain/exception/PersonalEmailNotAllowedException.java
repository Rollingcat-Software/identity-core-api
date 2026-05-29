package com.fivucsas.identity.domain.exception;

/**
 * Thrown by public self-service tenant onboarding when the admin email's domain
 * is a public / free / disposable provider (e.g. gmail.com, mailinator.com).
 *
 * <p>A real organisation signs up with its OWN corporate domain — this both
 * keeps the tenant directory clean and strengthens the domain-ownership story
 * (the claimed domain should be one the org actually controls). Normal
 * per-user registration ({@code /auth/register}) is NOT affected.</p>
 *
 * <p>Mapped by {@link com.fivucsas.identity.exception.GlobalExceptionHandler}
 * to HTTP 422 Unprocessable Entity.</p>
 */
public class PersonalEmailNotAllowedException extends DomainException {

    private final String emailDomain;

    public PersonalEmailNotAllowedException(String emailDomain) {
        super("Please sign up with your organization email, not a personal/free email provider.",
                "PERSONAL_EMAIL_NOT_ALLOWED");
        this.emailDomain = emailDomain;
    }

    public String getEmailDomain() {
        return emailDomain;
    }
}
