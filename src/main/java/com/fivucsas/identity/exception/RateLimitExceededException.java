package com.fivucsas.identity.exception;

/**
 * Exception thrown when rate limit is exceeded.
 *
 * @author FIVUCSAS Team
 * @since 1.0.0
 */
public class RateLimitExceededException extends RuntimeException {

    private final long retryAfterSeconds;

    public RateLimitExceededException(String message, long retryAfterSeconds) {
        super(message);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
