package com.fivucsas.identity.infrastructure.health;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Health indicator for the external biometric service (FastAPI).
 * Reports UP/DOWN status in the /actuator/health endpoint.
 */
@Component
@Slf4j
public class BiometricServiceHealthIndicator implements HealthIndicator {

    private final RestClient restClient;
    private final String biometricServiceUrl;

    public BiometricServiceHealthIndicator(
            @Value("${biometric.service.url}") String biometricServiceUrl) {
        this.biometricServiceUrl = biometricServiceUrl;
        this.restClient = RestClient.builder()
                .baseUrl(biometricServiceUrl)
                .build();
    }

    @Override
    public Health health() {
        try {
            restClient.get()
                    .uri("/health")
                    .retrieve()
                    .toBodilessEntity();
            return Health.up()
                    .withDetail("url", biometricServiceUrl)
                    .build();
        } catch (Exception e) {
            log.debug("Biometric service health check failed: {}", e.getMessage());
            return Health.down()
                    .withDetail("url", biometricServiceUrl)
                    .withDetail("error", e.getMessage())
                    .build();
        }
    }
}
