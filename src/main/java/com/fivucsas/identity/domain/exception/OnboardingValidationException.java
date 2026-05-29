package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a public self-service tenant onboarding request
 * ({@code POST /api/v1/onboarding/register}) fails a semantic validation that
 * is not covered by bean-validation annotations on the request DTO — for
 * example, an admin email whose local-domain cannot be derived, or a slug that
 * normalises to an empty string.
 *
 * <p>Mapped by {@link com.fivucsas.identity.exception.GlobalExceptionHandler}
 * to HTTP 400 Bad Request.</p>
 */
public class OnboardingValidationException extends DomainException {

    public OnboardingValidationException(String message) {
        super(message, "ONBOARDING_VALIDATION_FAILED");
    }
}
