package com.fivucsas.identity.entity;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Tracks multi-step authentication sessions.
 * Each step verification updates steps_data. Tokens are only issued when all steps complete.
 */
@Entity
@Table(name = "mfa_sessions")
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class MfaSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * JPA-safe equality by immutable id (P2.10). See {@link User#equals(Object)}
     * for full rationale.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MfaSession other)) return false;
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return MfaSession.class.hashCode();
    }

    @Column(name = "session_token", nullable = false, unique = true, length = 128)
    private String sessionToken;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "flow_id", nullable = false)
    private UUID flowId;

    @Column(name = "current_step", nullable = false)
    @Builder.Default
    private int currentStep = 1;

    @Column(name = "total_steps", nullable = false)
    private int totalSteps;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "steps_data", columnDefinition = "jsonb", nullable = false)
    @Builder.Default
    private String stepsData = "[]";

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "text")
    private String userAgent;

    /**
     * OAuth 2.0 client_id the MFA session was initiated against (nullable).
     *
     * <p>Set by AuthController.login when the hosted-login page forwards the
     * OAuth client_id. When non-null, {@code /oauth2/authorize/complete} MUST
     * reject any code-mint attempt whose request body carries a different
     * client_id (cross-client code replay defense).
     *
     * <p>Null is permitted for the widget step-up MFA flow, which has no
     * bound client.
     */
    @Column(name = "client_id", length = 128)
    private String clientId;

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    /**
     * Marks the session as already spent by a downstream flow (e.g. OAuth2
     * authorization code mint). Once non-null, the session MUST be rejected
     * on subsequent reads — this is the anti-replay barrier.
     */
    @Column(name = "consumed_at")
    private Instant consumedAt;

    public boolean isExpired() {
        // Inclusive boundary: a session whose expiresAt equals "now" is
        // considered expired. Matches MfaSessionRepository.deleteExpiredSessions
        // which uses {@code expiresAt <= :now}. Edge-P2 #6, 2026-04-29.
        return !Instant.now().isBefore(expiresAt);
    }

    public boolean isCompleted() {
        return completedAt != null;
    }

    /**
     * Cancels this MFA session by forcing it to expired state.
     *
     * <p>We don't have a dedicated CANCELLED column (avoiding a migration for
     * this edge-case fix); instead {@code expiresAt} is fast-forwarded to now
     * so any subsequent {@code isExpired()} check returns true. The calling
     * code is responsible for writing the audit trail entry that captures
     * user-initiated cancellation as the reason. Post-audit 2026-04-24
     * login edge case #3.
     */
    public void cancel() {
        this.expiresAt = Instant.now().minusSeconds(1);
    }

    /** True once consume() has been called — session is single-use. */
    public boolean isConsumed() {
        return consumedAt != null;
    }

    /** Atomically mark as spent. Callers must persist inside the same TX. */
    public void consume() {
        this.consumedAt = Instant.now();
    }

    public void advanceStep() {
        this.currentStep++;
    }

    public void complete() {
        this.completedAt = Instant.now();
    }

    public boolean allStepsCompleted() {
        return currentStep > totalSteps;
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Appends a completed auth method reference (RFC 8176) to stepsData.
     * e.g. "pwd", "otp", "face", "fpt", "hwk", "voice"
     */
    public void addCompletedMethod(String amrValue) {
        try {
            List<String> methods = MAPPER.readValue(stepsData, new TypeReference<List<String>>() {});
            methods.add(amrValue);
            this.stepsData = MAPPER.writeValueAsString(methods);
        } catch (Exception e) {
            this.stepsData = "[\"" + amrValue + "\"]";
        }
    }

    /**
     * Returns the list of completed auth method references for the amr JWT claim.
     */
    public List<String> getCompletedMethods() {
        try {
            return MAPPER.readValue(stepsData, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }
}
