package com.fivucsas.identity.domain.exception;

/**
 * Thrown when authentication fails due to account being locked.
 * Account lockout occurs after consecutive failed login attempts.
 */
public class AccountLockedException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Account is temporarily locked due to multiple failed login attempts. Please try again later.";
    private static final String ERROR_CODE = "ACCOUNT_LOCKED";

    private final long remainingLockTimeSeconds;

    public AccountLockedException(long remainingLockTimeSeconds) {
        super(DEFAULT_MESSAGE, ERROR_CODE);
        this.remainingLockTimeSeconds = remainingLockTimeSeconds;
    }

    public AccountLockedException(String message, long remainingLockTimeSeconds) {
        super(message, ERROR_CODE);
        this.remainingLockTimeSeconds = remainingLockTimeSeconds;
    }

    public AccountLockedException(String message, long remainingLockTimeSeconds, Throwable cause) {
        super(message, ERROR_CODE, cause);
        this.remainingLockTimeSeconds = remainingLockTimeSeconds;
    }

    /**
     * Gets the remaining time in seconds until the account is unlocked.
     *
     * @return seconds remaining
     */
    public long getRemainingLockTimeSeconds() {
        return remainingLockTimeSeconds;
    }

    /**
     * Gets the remaining time in minutes until the account is unlocked.
     *
     * @return minutes remaining (rounded up)
     */
    public long getRemainingLockTimeMinutes() {
        return (remainingLockTimeSeconds + 59) / 60; // Round up
    }

    @Override
    public String getMessage() {
        long minutes = getRemainingLockTimeMinutes();
        return String.format("Account is locked. Please try again in %d minute%s.",
            minutes, minutes == 1 ? "" : "s");
    }
}
