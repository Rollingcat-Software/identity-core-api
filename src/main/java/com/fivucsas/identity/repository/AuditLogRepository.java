package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * JPA Repository for AuditLog entity.
 *
 * Provides data access methods for audit trail querying and management.
 * Audit logs are immutable - no update operations are provided.
 *
 * Following principles:
 * - Repository Pattern: Encapsulates data access logic
 * - Dependency Inversion: Domain defines contract, infrastructure implements
 * - Single Responsibility: Focused on audit log persistence
 *
 * @see com.fivucsas.identity.entity.AuditLog
 * @see com.fivucsas.identity.application.port.output.AuditLogPort
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    /**
     * Finds all audit logs for a specific tenant with pagination.
     *
     * @param tenantId the tenant identifier
     * @param pageable pagination parameters
     * @return page of audit logs
     */
    Page<AuditLog> findByTenantIdOrderByCreatedAtDesc(UUID tenantId, Pageable pageable);

    /**
     * Finds all audit logs for a specific user with pagination.
     *
     * @param userId   the user identifier
     * @param pageable pagination parameters
     * @return page of audit logs
     */
    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);

    /**
     * Finds audit logs by action type.
     *
     * @param action   the action type (e.g., "LOGIN", "USER_CREATE")
     * @param pageable pagination parameters
     * @return page of audit logs
     */
    Page<AuditLog> findByActionOrderByCreatedAtDesc(String action, Pageable pageable);

    /**
     * Finds audit logs for a tenant filtered by action.
     *
     * @param tenantId the tenant identifier
     * @param action   the action type
     * @param pageable pagination parameters
     * @return page of audit logs
     */
    Page<AuditLog> findByTenantIdAndActionOrderByCreatedAtDesc(
            UUID tenantId,
            String action,
            Pageable pageable
    );

    /**
     * Finds audit logs for a user filtered by action.
     *
     * @param userId   the user identifier
     * @param action   the action type
     * @param pageable pagination parameters
     * @return page of audit logs
     */
    Page<AuditLog> findByUserIdAndActionOrderByCreatedAtDesc(
            UUID userId,
            String action,
            Pageable pageable
    );

    /**
     * Finds failed operations for security monitoring.
     *
     * @param success  false to find failed operations
     * @param pageable pagination parameters
     * @return page of failed audit logs
     */
    Page<AuditLog> findBySuccessOrderByCreatedAtDesc(Boolean success, Pageable pageable);

    /**
     * Finds failed operations for a tenant.
     *
     * @param tenantId the tenant identifier
     * @param success  false to find failed operations
     * @param pageable pagination parameters
     * @return page of failed audit logs
     */
    Page<AuditLog> findByTenantIdAndSuccessOrderByCreatedAtDesc(
            UUID tenantId,
            Boolean success,
            Pageable pageable
    );

    /**
     * Finds audit logs by request ID for distributed tracing.
     *
     * @param requestId the request identifier
     * @return list of audit logs for the request
     */
    List<AuditLog> findByRequestIdOrderByCreatedAtAsc(UUID requestId);

    /**
     * Finds audit logs within a time range.
     *
     * @param tenantId the tenant identifier
     * @param start    start time (inclusive)
     * @param end      end time (inclusive)
     * @param pageable pagination parameters
     * @return page of audit logs
     */
    @Query("SELECT al FROM AuditLog al WHERE al.tenantId = :tenantId " +
           "AND al.createdAt BETWEEN :start AND :end " +
           "ORDER BY al.createdAt DESC")
    Page<AuditLog> findByTenantAndTimeRange(
            @Param("tenantId") UUID tenantId,
            @Param("start") Instant start,
            @Param("end") Instant end,
            Pageable pageable
    );

    /**
     * Finds slow operations (duration > threshold).
     *
     * @param thresholdMs minimum duration in milliseconds
     * @param pageable    pagination parameters
     * @return page of slow operations
     */
    @Query("SELECT al FROM AuditLog al WHERE al.durationMs > :thresholdMs " +
           "ORDER BY al.durationMs DESC, al.createdAt DESC")
    Page<AuditLog> findSlowOperations(
            @Param("thresholdMs") Integer thresholdMs,
            Pageable pageable
    );

    /**
     * Finds slow operations for a specific endpoint.
     *
     * @param endpoint    the API endpoint
     * @param thresholdMs minimum duration in milliseconds
     * @param pageable    pagination parameters
     * @return page of slow operations
     */
    @Query("SELECT al FROM AuditLog al WHERE al.endpoint = :endpoint " +
           "AND al.durationMs > :thresholdMs " +
           "ORDER BY al.durationMs DESC, al.createdAt DESC")
    Page<AuditLog> findSlowOperationsByEndpoint(
            @Param("endpoint") String endpoint,
            @Param("thresholdMs") Integer thresholdMs,
            Pageable pageable
    );

    /**
     * Counts audit logs for a user within a time range.
     * Useful for rate limiting and anomaly detection.
     *
     * @param userId the user identifier
     * @param start  start time (inclusive)
     * @param end    end time (inclusive)
     * @return count of audit logs
     */
    @Query("SELECT COUNT(al) FROM AuditLog al WHERE al.userId = :userId " +
           "AND al.createdAt BETWEEN :start AND :end")
    long countByUserAndTimeRange(
            @Param("userId") UUID userId,
            @Param("start") Instant start,
            @Param("end") Instant end
    );

    /**
     * Counts failed login attempts for a user within a time range.
     *
     * @param userId the user identifier
     * @param start  start time (inclusive)
     * @param end    end time (inclusive)
     * @return count of failed login attempts
     */
    @Query("SELECT COUNT(al) FROM AuditLog al WHERE al.userId = :userId " +
           "AND al.action LIKE '%LOGIN%' AND al.success = false " +
           "AND al.createdAt BETWEEN :start AND :end")
    long countFailedLoginsByUserAndTimeRange(
            @Param("userId") UUID userId,
            @Param("start") Instant start,
            @Param("end") Instant end
    );

    /**
     * Counts failed operations from an IP address.
     * Useful for detecting brute force attacks.
     *
     * @param ipAddress the IP address
     * @param start     start time (inclusive)
     * @param end       end time (inclusive)
     * @return count of failed operations
     */
    @Query("SELECT COUNT(al) FROM AuditLog al WHERE al.ipAddress = :ipAddress " +
           "AND al.success = false AND al.createdAt BETWEEN :start AND :end")
    long countFailedOperationsByIpAndTimeRange(
            @Param("ipAddress") String ipAddress,
            @Param("start") Instant start,
            @Param("end") Instant end
    );

    /**
     * Finds recent audit logs (last 30 days) for quick access.
     *
     * @param cutoff   timestamp cutoff (typically 30 days ago)
     * @param pageable pagination parameters
     * @return page of recent audit logs
     */
    @Query("SELECT al FROM AuditLog al WHERE al.createdAt >= :cutoff " +
           "ORDER BY al.createdAt DESC")
    Page<AuditLog> findRecentAuditLogs(
            @Param("cutoff") Instant cutoff,
            Pageable pageable
    );

    /**
     * Deletes audit logs older than the specified date.
     * Used for data retention policy enforcement.
     *
     * @param before delete logs created before this timestamp
     * @return number of deleted records
     */
    @Modifying
    @Query("DELETE FROM AuditLog al WHERE al.createdAt < :before")
    int deleteOldAuditLogs(@Param("before") Instant before);

    /**
     * Archives detailed audit data (removes old_values, new_values, metadata).
     * Used for tiered data retention.
     *
     * @param before archive logs created before this timestamp
     * @return number of archived records
     */
    @Modifying
    @Query("UPDATE AuditLog al SET al.oldValues = null, al.newValues = null, " +
           "al.enhancedMetadata = null WHERE al.createdAt < :before")
    int archiveDetailedAuditData(@Param("before") Instant before);

    /**
     * Finds audit logs by resource type and resource ID.
     * Useful for viewing history of a specific entity.
     *
     * @param resourceType the resource type (e.g., "USER", "ROLE")
     * @param resourceId   the resource identifier
     * @param pageable     pagination parameters
     * @return page of audit logs
     */
    Page<AuditLog> findByResourceTypeAndResourceIdOrderByCreatedAtDesc(
            String resourceType,
            UUID resourceId,
            Pageable pageable
    );

    /**
     * Checks if user has any recent activity.
     *
     * @param userId the user identifier
     * @param since  check for activity since this timestamp
     * @return true if user has activity
     */
    boolean existsByUserIdAndCreatedAtAfter(UUID userId, Instant since);
}
