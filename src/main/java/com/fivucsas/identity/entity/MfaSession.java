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
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isCompleted() {
        return completedAt != null;
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
