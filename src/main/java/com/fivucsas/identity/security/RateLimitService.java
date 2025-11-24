package com.fivucsas.identity.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limiting service using Bucket4j token bucket algorithm.
 *
 * Rate Limits (OWASP Recommendations):
 * - Login attempts: 5 per 15 minutes per IP
 * - Registration: 3 per hour per IP
 * - Password reset: 3 per hour per IP
 * - Biometric verification: 10 per minute per user
 * - API calls: 100 per minute per user
 *
 * Implementation:
 * - Token bucket algorithm (Bucket4j)
 * - Per-IP and per-user rate limiting
 * - Automatic token refill
 * - Thread-safe concurrent access
 *
 * @author FIVUCSAS Team
 * @since 1.0.0
 */
@Service
@Slf4j
public class RateLimitService {

    // Separate buckets for different endpoints
    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> registerBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> passwordResetBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> biometricBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> apiBuckets = new ConcurrentHashMap<>();

    /**
     * Checks if a login attempt is allowed for the given identifier (usually IP address).
     *
     * @param identifier unique identifier (IP address or user ID)
     * @return true if attempt is allowed, false if rate limit exceeded
     */
    public boolean allowLoginAttempt(String identifier) {
        Bucket bucket = loginBuckets.computeIfAbsent(identifier, k -> createLoginBucket());
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for login attempt from: {}", identifier);
        }

        return allowed;
    }

    /**
     * Checks if a registration attempt is allowed for the given identifier.
     *
     * @param identifier unique identifier (IP address)
     * @return true if attempt is allowed, false if rate limit exceeded
     */
    public boolean allowRegistrationAttempt(String identifier) {
        Bucket bucket = registerBuckets.computeIfAbsent(identifier, k -> createRegistrationBucket());
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for registration attempt from: {}", identifier);
        }

        return allowed;
    }

    /**
     * Checks if a password reset attempt is allowed for the given identifier.
     *
     * @param identifier unique identifier (IP address or email)
     * @return true if attempt is allowed, false if rate limit exceeded
     */
    public boolean allowPasswordResetAttempt(String identifier) {
        Bucket bucket = passwordResetBuckets.computeIfAbsent(identifier, k -> createPasswordResetBucket());
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for password reset attempt from: {}", identifier);
        }

        return allowed;
    }

    /**
     * Checks if a biometric verification attempt is allowed for the given user.
     *
     * @param userId user identifier
     * @return true if attempt is allowed, false if rate limit exceeded
     */
    public boolean allowBiometricVerification(String userId) {
        Bucket bucket = biometricBuckets.computeIfAbsent(userId, k -> createBiometricBucket());
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for biometric verification from user: {}", userId);
        }

        return allowed;
    }

    /**
     * Checks if an API call is allowed for the given user.
     *
     * @param userId user identifier
     * @return true if call is allowed, false if rate limit exceeded
     */
    public boolean allowApiCall(String userId) {
        Bucket bucket = apiBuckets.computeIfAbsent(userId, k -> createApiBucket());
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for API calls from user: {}", userId);
        }

        return allowed;
    }

    /**
     * Gets remaining time until next token is available (in seconds).
     *
     * @param identifier unique identifier
     * @param bucketType type of rate limit bucket
     * @return seconds until next attempt is allowed
     */
    public long getSecondsUntilRefill(String identifier, RateLimitType bucketType) {
        Bucket bucket = getBucket(identifier, bucketType);
        if (bucket == null) {
            return 0;
        }

        return bucket.estimateAbilityToConsume(1).getNanosToWaitForRefill() / 1_000_000_000;
    }

    /**
     * Resets rate limit for a specific identifier (admin function).
     *
     * @param identifier unique identifier
     * @param bucketType type of rate limit bucket
     */
    public void resetRateLimit(String identifier, RateLimitType bucketType) {
        Map<String, Bucket> bucketMap = getBucketMap(bucketType);
        if (bucketMap != null) {
            bucketMap.remove(identifier);
            log.info("Rate limit reset for identifier: {} (type: {})", identifier, bucketType);
        }
    }

    // Private helper methods

    private Bucket createLoginBucket() {
        // 5 attempts per 15 minutes
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(15)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket createRegistrationBucket() {
        // 3 attempts per hour
        Bandwidth limit = Bandwidth.classic(3, Refill.intervally(3, Duration.ofHours(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket createPasswordResetBucket() {
        // 3 attempts per hour
        Bandwidth limit = Bandwidth.classic(3, Refill.intervally(3, Duration.ofHours(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket createBiometricBucket() {
        // 10 attempts per minute
        Bandwidth limit = Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket createApiBucket() {
        // 100 requests per minute
        Bandwidth limit = Bandwidth.classic(100, Refill.intervally(100, Duration.ofMinutes(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket getBucket(String identifier, RateLimitType bucketType) {
        Map<String, Bucket> bucketMap = getBucketMap(bucketType);
        return bucketMap != null ? bucketMap.get(identifier) : null;
    }

    private Map<String, Bucket> getBucketMap(RateLimitType bucketType) {
        return switch (bucketType) {
            case LOGIN -> loginBuckets;
            case REGISTRATION -> registerBuckets;
            case PASSWORD_RESET -> passwordResetBuckets;
            case BIOMETRIC -> biometricBuckets;
            case API -> apiBuckets;
        };
    }

    /**
     * Rate limit bucket types.
     */
    public enum RateLimitType {
        LOGIN,
        REGISTRATION,
        PASSWORD_RESET,
        BIOMETRIC,
        API
    }
}
