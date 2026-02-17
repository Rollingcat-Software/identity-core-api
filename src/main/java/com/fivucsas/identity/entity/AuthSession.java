package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.domain.model.auth.OperationType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "auth_sessions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AuthSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "auth_flow_id", nullable = false)
    private AuthFlow authFlow;

    @Enumerated(EnumType.STRING)
    @Column(name = "operation_type", nullable = false, length = 30)
    private OperationType operationType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private AuthSessionStatus status = AuthSessionStatus.CREATED;

    @Column(name = "current_step_order", nullable = false)
    @Builder.Default
    private int currentStepOrder = 1;

    @Column(name = "client_platform", length = 20)
    private String clientPlatform;

    @Column(name = "client_device_id", length = 255)
    private String clientDeviceId;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "started_at", nullable = false)
    @Builder.Default
    private Instant startedAt = Instant.now();

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private String metadata = "{}";

    @OneToMany(mappedBy = "session", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<AuthSessionStep> sessionSteps = new ArrayList<>();

    public void markInProgress() {
        this.status = AuthSessionStatus.IN_PROGRESS;
    }

    public void markCompleted() {
        this.status = AuthSessionStatus.COMPLETED;
        this.completedAt = Instant.now();
    }

    public void markFailed() {
        this.status = AuthSessionStatus.FAILED;
        this.completedAt = Instant.now();
    }

    public void markExpired() {
        this.status = AuthSessionStatus.EXPIRED;
    }

    public void cancel() {
        this.status = AuthSessionStatus.CANCELLED;
        this.completedAt = Instant.now();
    }

    public void advanceStep() {
        this.currentStepOrder++;
    }

    public void assignUser(User user) {
        this.user = user;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(this.expiresAt);
    }

    public boolean isTerminal() {
        return status == AuthSessionStatus.COMPLETED
            || status == AuthSessionStatus.FAILED
            || status == AuthSessionStatus.EXPIRED
            || status == AuthSessionStatus.CANCELLED;
    }
}
