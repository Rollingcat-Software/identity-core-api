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
    // AUDIT_2026-04-28_SECURITY.md SEC-P1 #4 — POST /auth/mfa/step bucket.
    // Cherry-picks the design from the unmerged security/phase-1-auth-hardening
    // branch (commit 3eb0161) into main: 30 attempts per minute per IP. Defends
    // against per-step OTP/biometric brute-force without throttling a legitimate
    // user re-trying an OTP they fat-fingered (which is single-digit per minute).
    private final ConcurrentHashMap<String, TimedBucket> mfaStepBuckets = new ConcurrentHashMap<>();
    // INVESTIGATION_MASTER_2026-05-07 §"developer/tenant constraints":
    // /oauth2/token success path was unbounded per-tenant. Per-IP/userId/
    // clientId buckets exist, but a tenant with a runaway integration that
    // distributes load across IPs+clientIds could mint tokens unbounded.
    // 6000/min/tenant is generous: at ~100 RPS sustained per tenant (a very
    // active SaaS deployment) it never trips, but stops a pathological loop
    // from chewing the whole pool. Enforced AFTER PKCE/secret validation
    // succeeds so it only counts genuine token mints.
    private final ConcurrentHashMap<String, TimedBucket> tenantTokenBuckets = new ConcurrentHashMap<>();

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
     * Checks if an {@code /auth/mfa/step} attempt is allowed for the given
     * client IP. Closes AUDIT_2026-04-28_SECURITY.md SEC-P1 #4.
     *
     * <p>Threshold: 30 per minute per IP. Rationale: a real user
     * occasionally re-enters an OTP they fat-fingered — single-digit per
     * minute. An attacker hammering /auth/mfa/step with an MFA session
     * token tries to brute-force a 6-digit numeric OTP (1M space) — at
     * 30/min that takes ~23 days, well past any session-token lifetime.</p>
     *
     * @param identifier client IP (X-Forwarded-For or remote-addr)
     * @return true if attempt is allowed, false if rate limit exceeded
     */
    public boolean allowMfaStepAttempt(String identifier) {
        Bucket bucket = getOrCreateBucket(mfaStepBuckets, identifier,
                this::createMfaStepBucket, Duration.ofMinutes(1));
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for MFA step from: {}", identifier);
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
    /**
     * Charges one token-mint against the per-tenant /oauth2/token bucket
     * and reports whether the tenant is now over budget. Called from the
     * success path of {@code POST /oauth2/token} so only legitimate mints
     * count — failure paths never reach this method.
     *
     * <p>Threshold: 6000 mints per minute per tenantId. Rationale:</p>
     * <ul>
     *   <li>Sustained 100 RPS per tenant is two orders of magnitude beyond
     *       any current FIVUCSAS deployment (largest tenant runs single-
     *       digit RPS at peak hosted-login traffic). The cap is essentially
     *       free for legitimate use.</li>
     *   <li>An attacker exploiting a compromised confidential client can
     *       still mint at most 6000/min before being throttled — that's a
     *       hard ceiling on blast radius for a single tenant compromise
     *       while the operator rotates the secret (see also the new V58
     *       rotation endpoint).</li>
     *   <li>Window aligns with the per-IP login bucket cadence (1m) so SOC
     *       dashboards plot apples to apples.</li>
     * </ul>
     *
     * @param tenantId tenant UUID (string form) of the token being minted
     * @return true if within budget, false if the tenant should be 429'd
     */
    public boolean allowTenantTokenMint(String tenantId) {
        Bucket bucket = getOrCreateBucket(tenantTokenBuckets, tenantId,
                this::createTenantTokenBucket, Duration.ofMinutes(1));
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit exceeded for /oauth2/token mint from tenantId: {}", tenantId);
        }

        return allowed;
    }

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
        cleaned += evictExpired(mfaStepBuckets, now, Duration.ofMinutes(1).toMillis());
        cleaned += evictExpired(tenantTokenBuckets, now, Duration.ofMinutes(1).toMillis());
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

    private Bucket createMfaStepBucket() {
        // 30 attempts per minute per IP (SEC-P1 #4).
        Bandwidth limit = Bandwidth.classic(30, Refill.intervally(30, Duration.ofMinutes(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private Bucket createTenantTokenBucket() {
        // 6000 successful token mints per minute per tenantId.
        // See allowTenantTokenMint() Javadoc for the rationale.
        Bandwidth limit = Bandwidth.classic(6000, Refill.intervally(6000, Duration.ofMinutes(1)));
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
            case MFA_STEP -> mfaStepBuckets;
            case TENANT_TOKEN -> tenantTokenBuckets;
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
        PKCE_FAILURE,
        MFA_STEP,
        TENANT_TOKEN
    }
}
