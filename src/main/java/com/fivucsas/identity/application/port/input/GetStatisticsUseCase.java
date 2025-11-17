package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.response.StatisticsResponse;

/**
 * Input port for retrieving system statistics.
 *
 * This interface defines the contract for querying various
 * system statistics (user counts, verification counts, etc.).
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - statistics
 * - Dependency Inversion: Application defines the port
 * - CQRS: Query-only operation (no side effects)
 */
public interface GetStatisticsUseCase {

    /**
     * Retrieves system statistics.
     *
     * @return StatisticsResponse with various system metrics
     */
    StatisticsResponse execute();
}
