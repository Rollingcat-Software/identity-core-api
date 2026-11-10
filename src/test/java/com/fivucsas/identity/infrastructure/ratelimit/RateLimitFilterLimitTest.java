package com.fivucsas.identity.infrastructure.ratelimit;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitFilterLimitTest {

    @Test
    void limitFor_WhenDevbenchIntake_ShouldUseHourlyCap() {
        RateLimitFilter.Limit limit = RateLimitFilter.limitFor("/api/v1/devbench/runs");

        assertThat(limit.maxRequests()).isEqualTo(30);
        assertThat(limit.window()).isEqualTo(Duration.ofHours(1));
    }

    @Test
    void limitFor_WhenOnboardingRegister_ShouldKeepItsCap() {
        assertThat(RateLimitFilter.limitFor("/api/v1/onboarding/register"))
                .isEqualTo(new RateLimitFilter.Limit(5, Duration.ofHours(1)));
    }

    @Test
    void limitFor_WhenOtherPath_ShouldUseDefault() {
        assertThat(RateLimitFilter.limitFor("/api/v1/users")).isEqualTo(RateLimitFilter.DEFAULT_LIMIT);
    }
}
