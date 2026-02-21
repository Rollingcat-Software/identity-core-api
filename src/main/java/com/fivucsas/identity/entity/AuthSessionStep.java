package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.AuthStepStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_session_steps")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AuthSessionStep {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id", nullable = false)
    private AuthSession session;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "auth_flow_step_id", nullable = false)
    private AuthFlowStep authFlowStep;

    @Enumerated(EnumType.STRING)
    @Column(name = "method_type", nullable = false, length = 30)
    private AuthMethodType methodType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private AuthStepStatus status = AuthStepStatus.PENDING;

    @Column(name = "attempt_count", nullable = false)
    @Builder.Default
    private int attemptCount = 0;

    @Column(nullable = false)
    @Builder.Default
    private boolean delegated = false;

    @Column(name = "delegation_token", length = 255)
    private String delegationToken;

    @Column(name = "delegation_device_id", length = 255)
    private String delegationDeviceId;

    @Column(name = "delegation_expires")
    private Instant delegationExpires;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private String result = "{}";

    public void start() {
        this.status = AuthStepStatus.IN_PROGRESS;
        this.startedAt = Instant.now();
    }

    public void complete(String resultJson) {
        this.status = AuthStepStatus.COMPLETED;
        this.completedAt = Instant.now();
        this.result = resultJson != null ? resultJson : "{}";
    }

    public void fail(String resultJson) {
        this.status = AuthStepStatus.FAILED;
        this.completedAt = Instant.now();
        this.result = resultJson != null ? resultJson : "{}";
    }

    public void skip() {
        this.status = AuthStepStatus.SKIPPED;
        this.completedAt = Instant.now();
    }

    public void delegate(String token, String deviceId, Instant expires) {
        this.status = AuthStepStatus.DELEGATED;
        this.delegated = true;
        this.delegationToken = token;
        this.delegationDeviceId = deviceId;
        this.delegationExpires = expires;
    }

    public void incrementAttempts() {
        this.attemptCount++;
    }

    public boolean hasExceededMaxAttempts(int maxAttempts) {
        return this.attemptCount >= maxAttempts;
    }
}
