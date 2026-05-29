package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Entity representing audit logs for security and compliance tracking.
 *
 * Captures all significant actions in the system including:
 * - Authentication events (login, logout, failed attempts)
 * - Authorization changes (role assignments, permission grants)
 * - Data modifications (create, update, delete operations)
 * - Biometric operations (enrollment, verification)
 *
 * Following principles:
 * - Immutability: Audit logs should never be modified
 * - Traceability: Complete request context for incident investigation
 * - Compliance: Meets security audit requirements (SOC 2, ISO 27001)
 *
 * @see com.fivucsas.identity.application.port.output.AuditLogPort
 */
@Entity
@Table(name = "audit_logs")
// Defense-in-depth tenant isolation (P0-1). @FilterDef is global from User.java.
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Tenant isolation. Sentinel UUID 00000000-0000-0000-0000-000000000000 is
    // used by AuditLogAdapter for truly anonymous events (pre-auth /oauth2/*,
    // failed login, PKCE failures). DB constraint enforced by V61 NOT NULL.
    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    // User context (nullable for anonymous operations)
    @Column(name = "user_id")
    private UUID userId;

    // Action details
    @Column(nullable = false, length = 100)
    private String action;

    @Column(name = "resource_type", nullable = false, length = 100)
    private String resourceType;

    @Column(name = "resource_id")
    private UUID resourceId;

    // HTTP request details
    @Column(name = "http_method", length = 10)
    private String httpMethod;

    @Column(length = 500)
    private String endpoint;

    @Column(name = "status_code")
    private Integer statusCode;

    // Change tracking (stored as JSONB)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "old_values", columnDefinition = "jsonb")
    private Map<String, Object> oldValues;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "new_values", columnDefinition = "jsonb")
    private Map<String, Object> newValues;

    // Result
    @Column(nullable = false)
    private Boolean success;

    @Column(name = "error_message", columnDefinition = "text")
    private String errorMessage;

    // Client information (V5 columns)
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "text")
    private String userAgent;

    @Column(name = "device_id", length = 100)
    private String deviceId;

    // V8 enhancements
    @Column(name = "user_agent_v2", columnDefinition = "text")
    private String userAgentV2;

    @Column(name = "request_id")
    private UUID requestId;

    @Column(name = "duration_ms")
    private Integer durationMs;

    // Location data (stored as JSONB)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> location;

    // Performance metrics (V5)
    @Column(name = "response_time_ms")
    private Integer responseTimeMs;

    // Flexible metadata storage (V5)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> metadata = Map.of();

    // Enhanced metadata (V8) - for additional context
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "enhanced_metadata", columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> enhancedMetadata = Map.of();

    // Timestamp (immutable)
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Checks if this audit log represents a security-sensitive event.
     *
     * @return true if the action is security-related
     */
    public boolean isSecurityEvent() {
        if (action == null) {
            return false;
        }
        return action.contains("LOGIN") ||
               action.contains("AUTH") ||
               action.contains("PERMISSION") ||
               action.contains("ROLE") ||
               action.contains("BIOMETRIC");
    }

    /**
     * Checks if this audit log represents a failed operation.
     *
     * @return true if the operation failed
     */
    public boolean isFailed() {
        return Boolean.FALSE.equals(success);
    }

    /**
     * Checks if this operation was slow (over 1 second).
     *
     * @return true if duration exceeds 1000ms
     */
    public boolean isSlowOperation() {
        return durationMs != null && durationMs > 1000;
    }

    /**
     * Gets the effective user agent (prioritizes V8 field).
     *
     * @return the user agent string
     */
    public String getEffectiveUserAgent() {
        return userAgentV2 != null ? userAgentV2 : userAgent;
    }

    /**
     * Gets the effective duration (prioritizes V8 field).
     *
     * @return the duration in milliseconds
     */
    public Integer getEffectiveDuration() {
        return durationMs != null ? durationMs : responseTimeMs;
    }
}
