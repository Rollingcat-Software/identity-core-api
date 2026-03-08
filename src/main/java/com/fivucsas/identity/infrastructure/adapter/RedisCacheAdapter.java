package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.CachePort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Redis implementation of CachePort.
 *
 * Provides distributed caching using Redis for:
 * - User lookup caching
 * - JWT token blacklist
 * - Permission caching
 * - Rate limiting data
 *
 * Following principles:
 * - Adapter Pattern: Adapts Redis to our CachePort
 * - Dependency Inversion: Application defines port, infrastructure implements
 * - Fail-Safe: Graceful degradation if Redis is unavailable
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RedisCacheAdapter implements CachePort {

    private final RedisTemplate<String, Object> redisTemplate;

    @Override
    public void put(String key, Object value, Duration ttl) {
        try {
            redisTemplate.opsForValue().set(key, value, ttl.toMillis(), TimeUnit.MILLISECONDS);
            log.debug("Cached value for key: {} with TTL: {}", key, ttl);
        } catch (Exception e) {
            log.error("Failed to cache value for key: {}", key, e);
        }
    }

    @Override
    public Optional<Object> get(String key) {
        try {
            Object value = redisTemplate.opsForValue().get(key);
            log.debug("Retrieved cache for key: {}, found: {}", key, value != null);
            return Optional.ofNullable(value);
        } catch (Exception e) {
            log.error("Failed to retrieve cache for key: {}", key, e);
            return Optional.empty();
        }
    }

    @Override
    public void evict(String key) {
        try {
            Boolean deleted = redisTemplate.delete(key);
            log.debug("Evicted cache for key: {}, success: {}", key, deleted);
        } catch (Exception e) {
            log.error("Failed to evict cache for key: {}", key, e);
        }
    }

    @Override
    public boolean exists(String key) {
        try {
            Boolean exists = redisTemplate.hasKey(key);
            return Boolean.TRUE.equals(exists);
        } catch (Exception e) {
            log.error("Failed to check existence for key: {}", key, e);
            return false;
        }
    }

    @Override
    public void clear() {
        try {
            redisTemplate.getConnectionFactory().getConnection().flushDb();
            log.warn("Cleared all cache entries");
        } catch (Exception e) {
            log.error("Failed to clear cache", e);
        }
    }

    @Override
    public void addToSet(String key, String value, Duration ttl) {
        try {
            redisTemplate.opsForSet().add(key, value);
            redisTemplate.expire(key, ttl.toMillis(), TimeUnit.MILLISECONDS);
            log.debug("Added value to set: {}, TTL: {}", key, ttl);
        } catch (Exception e) {
            log.error("Failed to add value to set: {}", key, e);
        }
    }

    @Override
    public boolean existsInSet(String key, String value) {
        try {
            Boolean isMember = redisTemplate.opsForSet().isMember(key, value);
            return Boolean.TRUE.equals(isMember);
        } catch (Exception e) {
            log.error("Failed to check set membership for key: {}", key, e);
            return false;
        }
    }

    @Override
    public void removeFromSet(String key, String value) {
        try {
            Long removed = redisTemplate.opsForSet().remove(key, value);
            log.debug("Removed value from set: {}, count: {}", key, removed);
        } catch (Exception e) {
            log.error("Failed to remove value from set: {}", key, e);
        }
    }
}
