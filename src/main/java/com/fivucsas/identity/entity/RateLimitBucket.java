package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Entity representing a rate limit bucket for API request throttling.
 *
 * Implements the Token Bucket algorithm for distributed rate limiting:
 * - Each bucket has a maximum capacity (max_tokens)
 * - Tokens are refilled at a constant rate (refill_rate per second)
 * - Each request consumes tokens
 * - Requests are blocked when bucket is empty
 *
 * Supports multiple rate limit types:
 * - IP-based: Rate limit by client IP address
 * - User-based: Rate limit by authenticated user
 * - Endpoint-based: Rate limit specific API endpoints
 * - Tenant-based: Rate limit entire tenant
 * - Global: System-wide rate limiting
 *
 * Following principles:
 * - Persistence: Rate limits survive service restarts
 * - Atomicity: Token consumption is atomic via database functions
 * - Scalability: Supports distributed systems with shared state
 *
 * @see com.fivucsas.identity.repository.RateLimitBucketRepository
 */
@Entity
@Table(name = "rate_limit_buckets")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RateLimitBucket {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Unique key identifying the rate limit bucket.
     * Examples:
     * - "ip:192.168.1.1" for IP-based limiting
     * - "user:550e8400-e29b-41d4-a716-446655440000" for user-based
     * - "endpoint:/api/auth/login" for endpoint-based
     * - "tenant:550e8400-e29b-41d4-a716-446655440000" for tenant-based
     */
    @Column(name = "limit_key", nullable = false, unique = true, length = 500)
    private String limitKey;

    /**
     * Type of rate limit for categorization and management.
     * Values: IP, USER, ENDPOINT, TENANT, GLOBAL
     */
    @Column(name = "limit_type", nullable = false, length = 50)
    private String limitType;

    /**
     * Current number of tokens in the bucket.
     * Decrements with each request, refills over time.
     */
    @Column(name = "bucket_tokens", nullable = false, precision = 10, scale = 2)
    @Builder.Default
    private BigDecimal bucketTokens = BigDecimal.ZERO;

    /**
     * Maximum capacity of the bucket (burst limit).
     * Allows short bursts of traffic up to this limit.
     */
    @Column(name = "max_tokens", nullable = false, precision = 10, scale = 2)
    @Builder.Default
    private BigDecimal maxTokens = new BigDecimal("100");

    /**
     * Rate at which tokens are refilled (tokens per second).
     * Determines sustained request rate.
     */
    @Column(name = "refill_rate", nullable = false, precision = 10, scale = 2)
    @Builder.Default
    private BigDecimal refillRate = new BigDecimal("10");

    /**
     * Last time tokens were refilled.
     * Used to calculate tokens to add since last refill.
     */
    @Column(name = "last_refill_at", nullable = false)
    @Builder.Default
    private Instant lastRefillAt = Instant.now();

    /**
     * Optional expiration for automatic cleanup.
     * Useful for temporary rate limits.
     */
    @Column(name = "expires_at")
    private Instant expiresAt;

    // Tracking metrics
    @Column(name = "request_count")
    @Builder.Default
    private Long requestCount = 0L;

    @Column(name = "blocked_count")
    @Builder.Default
    private Long blockedCount = 0L;

    @Column(name = "first_seen_at", nullable = false, updatable = false)
    @CreationTimestamp
    private Instant firstSeenAt;

    @Column(name = "last_seen_at", nullable = false)
    @Builder.Default
    private Instant lastSeenAt = Instant.now();

    // Flexible metadata storage
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> metadata = Map.of();

    // Timestamps
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /**
     * Checks if the bucket has expired.
     *
     * @return true if expiresAt is set and in the past
     */
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    /**
     * Checks if the bucket is empty (no tokens available).
     *
     * @return true if no tokens available
     */
    public boolean isEmpty() {
        return bucketTokens.compareTo(BigDecimal.ZERO) <= 0;
    }

    /**
     * Checks if the bucket is full.
     *
     * @return true if at maximum capacity
     */
    public boolean isFull() {
        return bucketTokens.compareTo(maxTokens) >= 0;
    }

    /**
     * Calculates the percentage of bucket capacity used.
     *
     * @return capacity percentage (0-100)
     */
    public double getCapacityPercent() {
        if (maxTokens.compareTo(BigDecimal.ZERO) == 0) {
            return 0.0;
        }
        return bucketTokens.divide(maxTokens, 4, BigDecimal.ROUND_HALF_UP)
                .multiply(new BigDecimal("100"))
                .doubleValue();
    }

    /**
     * Calculates the block rate percentage.
     *
     * @return percentage of requests blocked (0-100)
     */
    public double getBlockRatePercent() {
        if (requestCount == 0) {
            return 0.0;
        }
        return (blockedCount.doubleValue() / requestCount.doubleValue()) * 100.0;
    }

    /**
     * Checks if this is a hot bucket (frequently accessed).
     * Hot buckets are those accessed in the last hour.
     *
     * @return true if accessed in the last hour
     */
    public boolean isHot() {
        return lastSeenAt.isAfter(Instant.now().minusSeconds(3600));
    }

    /**
     * Checks if this is a stale bucket (not accessed recently).
     * Stale buckets haven't been accessed in 24 hours.
     *
     * @return true if not accessed in 24 hours
     */
    public boolean isStale() {
        return lastSeenAt.isBefore(Instant.now().minusSeconds(86400));
    }

    /**
     * Increments request count.
     */
    public void incrementRequestCount() {
        this.requestCount++;
        this.lastSeenAt = Instant.now();
    }

    /**
     * Increments blocked count.
     */
    public void incrementBlockedCount() {
        this.blockedCount++;
        this.lastSeenAt = Instant.now();
    }

    /**
     * Resets the bucket to full capacity.
     */
    public void reset() {
        this.bucketTokens = this.maxTokens;
        this.lastRefillAt = Instant.now();
        this.requestCount = 0L;
        this.blockedCount = 0L;
    }
}
