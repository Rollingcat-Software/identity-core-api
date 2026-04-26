package com.fivucsas.identity.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Rate limiting service using Bucket4j token bucket algorithm.
 *
 * Rate Limits:
 * - Login attempts: 10 per 5 minutes per IP
 * - Registration: 5 per hour per IP
 * - Password reset: 5 per hour per IP
 * - Biometric verification: 20 per minute per user
 * - API calls: 100 per minute per user
 *
 * Implementation:
 * - Token bucket algorithm (Bucket4j)
 * - Per-IP and per-user rate limiting
 * - Automatic token refill
 * - Thread-safe concurrent access
 * - Size-bounded maps with periodic TTL-based eviction
 *
 * @author FIVUCSAS Team
 * @since 1.0.0
 */
@Service
@Slf4j
public class RateLimitService {

    /**
     * Maximum number of entries per bucket map to prevent unbounded memory growth.
     * After this limit, oldest entries are evicted.
     */
    private static final int MAX_ENTRIES_PER_MAP = 10_000;

    // Separate buckets for different endpoints (with creation timestamps for eviction)
    private final ConcurrentHashMap<String, TimedBucket> loginBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, TimedBucket> registerBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, TimedBucket> passwordResetBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, TimedBucket> biometricBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, TimedBucket> apiBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, TimedBucket> exportBuckets = new ConcurrentHashMap<>();
    // Phase D5b — per-clientId PKCE failure throttling at /oauth2/token. Only
    // FAILURES are counted (success path never hits this bucket), so legitimate
    // high-traffic clients never get throttled; an attacker hammering one
    // clientId with bad code_verifiers does.
    private final ConcurrentHashMap<String, TimedBucket> pkceFailureBuckets = new ConcurrentHashMap<>();

    /**
     * Checks if a login attempt is allowed for the given identifier (usually IP address).
     *
     * @param identifier unique identifier (IP address or user ID)
     * @return true if attempt is allowed, false if rate limit exceeded
     */
    public boolean allowLoginAttempt(String identifier) {
        Bucket bucket = getOrCreateBucket(loginBuckets, identifier, this::createLoginBucket, Duration.ofMinutes(5));
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
        Bucket bucket = getOrCreateBucket(registerBuckets, identifier, this::createRegistrationBucket, Duration.ofHours(1));
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
        Bucket bucket = getOrCreateBucket(passwordResetBuckets, identifier, this::createPasswordResetBucket, Duration.ofHours(1));
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
        Bucket bucket = getOrCreateBucket(biometricBuckets, userId, this::createBiometricBucket, Duration.ofMinutes(1));
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
        Bucket bucket = getOrCreateBucket(apiBuckets, userId, this::createApiBucket, Duration.ofMinutes(1));
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for API calls from user: {}", userId);
        }

        return allowed;
    }

    /**
     * Checks if a GDPR data-export request is allowed for the given user.
     * Exports are expensive (cross-table aggregation) and should be rare — 1 per hour
     * per user matches the GDPR Art. 12 §5 "reasonable-effort" threshold for repeat requests.
     *
     * @param userId user identifier (not IP — export is per-user, not per-IP)
     * @return true if export is allowed, false if rate limit exceeded
     */
    public boolean allowDataExport(String userId) {
        Bucket bucket = getOrCreateBucket(exportBuckets, userId, this::createExportBucket, Duration.ofHours(1));
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for GDPR data export from user: {}", userId);
        }

        return allowed;
    }

    /**
     * Records a PKCE / authorization-code-exchange failure for the given
     * {@code clientId} and reports whether the client is now over the
     * failure-rate threshold (Phase D5b).
     *
     * <p>Threshold: 30 failures per 5 minutes per clientId. Rationale:</p>
     * <ul>
     *   <li>Legitimate confidential clients only fail when a user fat-fingers
     *       a verifier in a custom integration — single-digit per minute at
     *       worst even for a popular tenant.</li>
     *   <li>30/5min leaves enough headroom that no genuine integration trips,
     *       while limiting an attacker to ~360 verifier guesses per hour per
     *       intercepted code (codes expire after 10 min anyway, so the
     *       practical guess budget is ~60 per code).</li>
     *   <li>Aligns with login-attempt bucket cadence (10/5min) — same window
     *       for SOC dashboards.</li>
     * </ul>
     *
     * <p>Only failures consume tokens. Success paths never call this method,
     * so a busy production client minting thousands of tokens an hour is
     * unaffected.</p>
     *
     * @param clientId OAuth2 client_id from the failed /oauth2/token request
     * @return true if the failure is allowed (within budget), false if the
     *         client is now over the threshold and the response should be 429
     */
    public boolean recordAndAllowPkceFailure(String clientId) {
        Bucket bucket = getOrCreateBucket(pkceFailureBuckets, clientId,
                this::createPkceFailureBucket, Duration.ofMinutes(5));
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for PKCE failures from clientId: {}", clientId);
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
        ConcurrentHashMap<String, TimedBucket> bucketMap = getBucketMap(bucketType);
        if (bucketMap == null) return 0;
        TimedBucket timedBucket = bucketMap.get(identifier);
        if (timedBucket == null) return 0;

        return timedBucket.bucket.estimateAbilityToConsume(1).getNanosToWaitForRefill() / 1_000_000_000;
    }

    /**
     * Resets rate limit for a specific identifier (admin function).
     *
     * @param identifier unique identifier
     * @param bucketType type of rate limit bucket
     */
    public void resetRateLimit(String identifier, RateLimitType bucketType) {
        ConcurrentHashMap<String, TimedBucket> bucketMap = getBucketMap(bucketType);
        if (bucketMap != null) {
            bucketMap.remove(identifier);
            log.info("Rate limit reset for identifier: {} (type: {})", identifier, bucketType);
        }
    }

    /**
     * Periodic cleanup of expired bucket entries to prevent memory leaks.
     * Runs every 5 minutes.
     */
    @Scheduled(fixedRate = 300_000)
    public void cleanupExpiredBuckets() {
        long now = System.currentTimeMillis();
        int cleaned = 0;
        cleaned += evictExpired(loginBuckets, now, Duration.ofMinutes(5).toMillis());
        cleaned += evictExpired(registerBuckets, now, Duration.ofHours(1).toMillis());
        cleaned += evictExpired(passwordResetBuckets, now, Duration.ofHours(1).toMillis());
        cleaned += evictExpired(biometricBuckets, now, Duration.ofMinutes(1).toMillis());
        cleaned += evictExpired(apiBuckets, now, Duration.ofMinutes(1).toMillis());
        cleaned += evictExpired(exportBuckets, now, Duration.ofHours(1).toMillis());
        cleaned += evictExpired(pkceFailureBuckets, now, Duration.ofMinutes(5).toMillis());
        if (cleaned > 0) {
            log.debug("Evicted {} expired rate limit bucket entries", cleaned);
        }
    }

    // Private helper methods

    private Bucket getOrCreateBucket(ConcurrentHashMap<String, TimedBucket> map,
                                      String identifier,
                                      java.util.function.Supplier<Bucket> bucketFactory,
                                      Duration ttl) {
        // Enforce size limit
        if (map.size() >= MAX_ENTRIES_PER_MAP && !map.containsKey(identifier)) {
            // Evict expired entries first
            long now = System.currentTimeMillis();
            map.entrySet().removeIf(e -> now - e.getValue().createdAt > ttl.toMillis() * 2);

            // If still over limit after cleanup, evict oldest 10%
            if (map.size() >= MAX_ENTRIES_PER_MAP) {
                long cutoff = now - ttl.toMillis();
                map.entrySet().removeIf(e -> e.getValue().createdAt < cutoff);
                log.warn("Rate limit map at capacity ({}), evicted expired entries", MAX_ENTRIES_PER_MAP);
            }
        }

        TimedBucket timedBucket = map.computeIfAbsent(identifier,
                k -> new TimedBucket(bucketFactory.get(), System.currentTimeMillis()));
        return timedBucket.bucket;
    }

    private int evictExpired(ConcurrentHashMap<String, TimedBucket> map, long now, long ttlMs) {
        int before = map.size();
        // Evict entries that are 2x older than their TTL (generous, ensures refill happened)
        map.entrySet().removeIf(e -> now - e.getValue().createdAt > ttlMs * 2);
        return before - map.size();
    }

    private Bucket createLoginBucket() {
        // 10 attempts per 5 minutes
        Bandwidth limit = Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(5)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket createRegistrationBucket() {
        // 5 attempts per hour
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofHours(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket createPasswordResetBucket() {
        // 5 attempts per hour
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofHours(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket createBiometricBucket() {
        // 20 attempts per minute
        Bandwidth limit = Bandwidth.classic(20, Refill.intervally(20, Duration.ofMinutes(1)));
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

    private Bucket createExportBucket() {
        // 1 GDPR data-export per hour (Art. 12 §5 reasonable-effort threshold)
        Bandwidth limit = Bandwidth.classic(1, Refill.intervally(1, Duration.ofHours(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket createPkceFailureBucket() {
        // 30 PKCE/code-exchange failures per 5 minutes per clientId (Phase D5b).
        // See recordAndAllowPkceFailure() Javadoc for threshold rationale.
        Bandwidth limit = Bandwidth.classic(30, Refill.intervally(30, Duration.ofMinutes(5)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private ConcurrentHashMap<String, TimedBucket> getBucketMap(RateLimitType bucketType) {
        return switch (bucketType) {
            case LOGIN -> loginBuckets;
            case REGISTRATION -> registerBuckets;
            case PASSWORD_RESET -> passwordResetBuckets;
            case BIOMETRIC -> biometricBuckets;
            case API -> apiBuckets;
            case EXPORT -> exportBuckets;
            case PKCE_FAILURE -> pkceFailureBuckets;
        };
    }

    /**
     * Wrapper to track bucket creation time for eviction.
     */
    private record TimedBucket(Bucket bucket, long createdAt) {}

    /**
     * Rate limit bucket types.
     */
    public enum RateLimitType {
        LOGIN,
        REGISTRATION,
        PASSWORD_RESET,
        BIOMETRIC,
        API,
        EXPORT,
        PKCE_FAILURE
    }
}
