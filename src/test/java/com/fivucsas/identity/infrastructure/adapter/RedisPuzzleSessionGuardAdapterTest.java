package com.fivucsas.identity.infrastructure.adapter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("RedisPuzzleSessionGuardAdapter — puzzle create cap + trace-contract record")
class RedisPuzzleSessionGuardAdapterTest {

    private StringRedisTemplate redis;
    private ValueOperations<String, String> ops;
    private RedisPuzzleSessionGuardAdapter adapter;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);
        adapter = new RedisPuzzleSessionGuardAdapter(redis);
    }

    @Test
    @DisplayName("first increment sets the TTL; later ones do not")
    void increment_setsTtlOnFirst() {
        String key = RedisPuzzleSessionGuardAdapter.CREATES_PREFIX + "k";
        when(ops.increment(key)).thenReturn(1L, 2L);
        assertThat(adapter.incrementCreates("k", Duration.ofMinutes(30))).isEqualTo(1L);
        verify(redis).expire(key, Duration.ofMinutes(30));
        assertThat(adapter.incrementCreates("k", Duration.ofMinutes(30))).isEqualTo(2L);
        verify(redis, org.mockito.Mockito.times(1)).expire(key, Duration.ofMinutes(30));
    }

    @Test
    @DisplayName("Redis down → IllegalStateException (caller fails closed)")
    void increment_redisDown_throws() {
        when(ops.increment(anyString())).thenThrow(new RedisConnectionFailureException("down"));
        assertThatThrownBy(() -> adapter.incrementCreates("k", Duration.ofMinutes(1)))
                .isInstanceOf(IllegalStateException.class);
        verify(redis, never()).expire(anyString(), org.mockito.ArgumentMatchers.any(Duration.class));
    }

    @Test
    @DisplayName("contract record round-trips; a read failure is 'unknown' (empty)")
    void contractRecord() {
        String key = RedisPuzzleSessionGuardAdapter.CONTRACT_PREFIX + "sid";
        adapter.recordTraceContract("sid", "v2", Duration.ofMinutes(10));
        verify(ops).set(key, "v2", Duration.ofMinutes(10));
        when(ops.get(key)).thenReturn("v2");
        assertThat(adapter.traceContractFor("sid")).contains("v2");
        when(ops.get(key)).thenThrow(new RedisConnectionFailureException("down"));
        assertThat(adapter.traceContractFor("sid")).isEmpty();
    }
}
