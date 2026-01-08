package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.RateLimitBucket;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * JPA Repository for RateLimitBucket entity.
 *
 * Provides data access methods for rate limiting operations.
 * Token consumption should use database functions for atomicity.
 *
 * Following principles:
 * - Repository Pattern: Encapsulates data access logic
 * - Atomicity: Critical operations use database functions
 * - Performance: Indexed queries for fast lookups
 *
 * @see com.fivucsas.identity.entity.RateLimitBucket
 */
@Repository
public interface RateLimitBucketRepository extends JpaRepository<RateLimitBucket, UUID> {

    /**
     * Finds a rate limit bucket by its key.
     *
     * @param limitKey the unique bucket key
     * @return optional rate limit bucket
     */
    Optional<RateLimitBucket> findByLimitKey(String limitKey);

    /**
     * Finds all rate limit buckets of a specific type.
     *
     * @param limitType the type (IP, USER, ENDPOINT, TENANT, GLOBAL)
     * @param pageable  pagination parameters
     * @return page of rate limit buckets
     */
    Page<RateLimitBucket> findByLimitTypeOrderByLastSeenAtDesc(String limitType, Pageable pageable);

    /**
     * Finds expired rate limit buckets for cleanup.
     *
     * @return list of expired buckets
     */
    @Query("SELECT rlb FROM RateLimitBucket rlb WHERE rlb.expiresAt IS NOT NULL " +
           "AND rlb.expiresAt < CURRENT_TIMESTAMP")
    List<RateLimitBucket> findExpiredBuckets();

    /**
     * Finds stale rate limit buckets (not accessed in specified duration).
     *
     * @param cutoff timestamp cutoff (e.g., 24 hours ago)
     * @return list of stale buckets
     */
    @Query("SELECT rlb FROM RateLimitBucket rlb WHERE rlb.lastSeenAt < :cutoff " +
           "AND rlb.expiresAt IS NULL")
    List<RateLimitBucket> findStaleBuckets(@Param("cutoff") Instant cutoff);

    /**
     * Finds hot buckets (frequently accessed).
     *
     * @param cutoff   timestamp cutoff (e.g., 1 hour ago)
     * @param pageable pagination parameters
     * @return page of hot buckets
     */
    @Query("SELECT rlb FROM RateLimitBucket rlb WHERE rlb.lastSeenAt >= :cutoff " +
           "ORDER BY rlb.lastSeenAt DESC")
    Page<RateLimitBucket> findHotBuckets(@Param("cutoff") Instant cutoff, Pageable pageable);

    /**
     * Finds buckets that need refilling (not at max capacity).
     *
     * @param pageable pagination parameters
     * @return page of buckets needing refill
     */
    @Query("SELECT rlb FROM RateLimitBucket rlb WHERE rlb.bucketTokens < rlb.maxTokens " +
           "ORDER BY rlb.lastRefillAt ASC")
    Page<RateLimitBucket> findBucketsNeedingRefill(Pageable pageable);

    /**
     * Finds buckets with high block rate.
     *
     * @param minBlockRate minimum block rate percentage
     * @param pageable     pagination parameters
     * @return page of heavily blocked buckets
     */
    @Query("SELECT rlb FROM RateLimitBucket rlb WHERE rlb.requestCount > 0 " +
           "AND (rlb.blockedCount * 100.0 / rlb.requestCount) >= :minBlockRate " +
           "ORDER BY rlb.blockedCount DESC")
    Page<RateLimitBucket> findHighBlockRateBuckets(
            @Param("minBlockRate") double minBlockRate,
            Pageable pageable
    );

    /**
     * Finds empty buckets (no tokens available).
     *
     * @param pageable pagination parameters
     * @return page of empty buckets
     */
    @Query("SELECT rlb FROM RateLimitBucket rlb WHERE rlb.bucketTokens <= 0 " +
           "ORDER BY rlb.lastSeenAt DESC")
    Page<RateLimitBucket> findEmptyBuckets(Pageable pageable);

    /**
     * Counts rate limit buckets by type.
     *
     * @param limitType the type (IP, USER, ENDPOINT, TENANT, GLOBAL)
     * @return count of buckets
     */
    long countByLimitType(String limitType);

    /**
     * Checks if a rate limit bucket exists for the given key.
     *
     * @param limitKey the unique bucket key
     * @return true if bucket exists
     */
    boolean existsByLimitKey(String limitKey);

    /**
     * Deletes expired rate limit buckets.
     *
     * @return number of deleted records
     */
    @Modifying
    @Query("DELETE FROM RateLimitBucket rlb WHERE rlb.expiresAt IS NOT NULL " +
           "AND rlb.expiresAt < CURRENT_TIMESTAMP")
    int deleteExpiredBuckets();

    /**
     * Deletes stale rate limit buckets (not accessed in specified duration).
     *
     * @param cutoff timestamp cutoff (e.g., 24 hours ago)
     * @return number of deleted records
     */
    @Modifying
    @Query("DELETE FROM RateLimitBucket rlb WHERE rlb.lastSeenAt < :cutoff " +
           "AND rlb.expiresAt IS NULL")
    int deleteStaleBuckets(@Param("cutoff") Instant cutoff);

    /**
     * Resets a rate limit bucket to full capacity.
     *
     * @param limitKey the unique bucket key
     * @param now current timestamp
     * @return number of updated records
     */
    @Modifying
    @Query("UPDATE RateLimitBucket rlb SET rlb.bucketTokens = rlb.maxTokens, " +
           "rlb.lastRefillAt = :now, rlb.requestCount = 0, " +
           "rlb.blockedCount = 0 WHERE rlb.limitKey = :limitKey")
    int resetBucket(@Param("limitKey") String limitKey, @Param("now") Instant now);

    /**
     * Resets all rate limit buckets of a specific type.
     *
     * @param limitType the type (IP, USER, ENDPOINT, TENANT, GLOBAL)
     * @param now current timestamp
     * @return number of updated records
     */
    @Modifying
    @Query("UPDATE RateLimitBucket rlb SET rlb.bucketTokens = rlb.maxTokens, " +
           "rlb.lastRefillAt = :now, rlb.requestCount = 0, " +
           "rlb.blockedCount = 0 WHERE rlb.limitType = :limitType")
    int resetBucketsByType(@Param("limitType") String limitType, @Param("now") Instant now);

    /**
     * Updates last seen timestamp for a bucket.
     *
     * @param limitKey the unique bucket key
     * @param now current timestamp
     * @return number of updated records
     */
    @Modifying
    @Query("UPDATE RateLimitBucket rlb SET rlb.lastSeenAt = :now " +
           "WHERE rlb.limitKey = :limitKey")
    int updateLastSeenAt(@Param("limitKey") String limitKey, @Param("now") Instant now);

    /**
     * Increments request count for a bucket.
     *
     * @param limitKey the unique bucket key
     * @param now current timestamp
     * @return number of updated records
     */
    @Modifying
    @Query("UPDATE RateLimitBucket rlb SET rlb.requestCount = rlb.requestCount + 1, " +
           "rlb.lastSeenAt = :now WHERE rlb.limitKey = :limitKey")
    int incrementRequestCount(@Param("limitKey") String limitKey, @Param("now") Instant now);

    /**
     * Increments blocked count for a bucket.
     *
     * @param limitKey the unique bucket key
     * @param now current timestamp
     * @return number of updated records
     */
    @Modifying
    @Query("UPDATE RateLimitBucket rlb SET rlb.blockedCount = rlb.blockedCount + 1, " +
           "rlb.lastSeenAt = :now WHERE rlb.limitKey = :limitKey")
    int incrementBlockedCount(@Param("limitKey") String limitKey, @Param("now") Instant now);

    /**
     * Finds all rate limit buckets for monitoring.
     *
     * @param pageable pagination parameters
     * @return page of buckets ordered by last seen
     */
    Page<RateLimitBucket> findAllByOrderByLastSeenAtDesc(Pageable pageable);

    /**
     * Gets total request count across all buckets.
     *
     * @return total requests
     */
    @Query("SELECT COALESCE(SUM(rlb.requestCount), 0) FROM RateLimitBucket rlb")
    long getTotalRequestCount();

    /**
     * Gets total blocked count across all buckets.
     *
     * @return total blocked requests
     */
    @Query("SELECT COALESCE(SUM(rlb.blockedCount), 0) FROM RateLimitBucket rlb")
    long getTotalBlockedCount();

    /**
     * Gets statistics for a specific rate limit type.
     *
     * @param limitType the type (IP, USER, ENDPOINT, TENANT, GLOBAL)
     * @return statistics object with count, requests, blocks
     */
    @Query("SELECT new map(COUNT(rlb) as count, " +
           "COALESCE(SUM(rlb.requestCount), 0) as totalRequests, " +
           "COALESCE(SUM(rlb.blockedCount), 0) as totalBlocked) " +
           "FROM RateLimitBucket rlb WHERE rlb.limitType = :limitType")
    Map<String, Object> getStatisticsByType(@Param("limitType") String limitType);
}
