package com.fivucsas.identity.domain.exception;

/**
 * Exception thrown when the cache (Redis) is unavailable and a fail-closed
 * operation is attempted (e.g., JWT blacklist check).
 */
public class CacheUnavailableException extends RuntimeException {

    public CacheUnavailableException(String message) {
        super(message);
    }

    public CacheUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
