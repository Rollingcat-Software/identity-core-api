package com.fivucsas.identity.application.port.output;

import java.time.Duration;
import java.util.Optional;

/**
 * Output port for caching operations.
 *
 * This interface defines the contract for cache operations.
 * Implementation can use Redis, Memcached, or any other caching solution.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - caching operations
 * - Dependency Inversion: Application defines contract, infrastructure implements
 * - Abstraction: Decouples from specific cache implementation
 */
public interface CachePort {

    /**
     * Stores a value in cache with TTL.
     *
     * @param key the cache key
     * @param value the value to cache
     * @param ttl time-to-live duration
     */
    void put(String key, Object value, Duration ttl);

    /**
     * Retrieves a value from cache.
     *
     * @param key the cache key
     * @return Optional containing the value if present
     */
    Optional<Object> get(String key);

    /**
     * Removes a value from cache.
     *
     * @param key the cache key
     */
    void evict(String key);

    /**
     * Checks if a key exists in cache.
     *
     * @param key the cache key
     * @return true if key exists
     */
    boolean exists(String key);

    /**
     * Clears all entries from cache.
     * Use with caution in production.
     */
    void clear();

    /**
     * Adds a value to a set in cache.
     * Useful for blacklists, whitelists, etc.
     *
     * @param key the set key
     * @param value the value to add
     * @param ttl time-to-live duration
     */
    void addToSet(String key, String value, Duration ttl);

    /**
     * Checks if a value exists in a set.
     *
     * @param key the set key
     * @param value the value to check
     * @return true if value exists in set
     */
    boolean existsInSet(String key, String value);

    /**
     * Removes a value from a set.
     *
     * @param key the set key
     * @param value the value to remove
     */
    void removeFromSet(String key, String value);
}
