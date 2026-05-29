package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.VerificationSessionStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "verification_sessions")
// Defense-in-depth tenant isolation (P0-1). @FilterDef is global from User.java.
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class VerificationSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "flow_id", nullable = false)
    private AuthFlow flow;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    @Builder.Default
    private VerificationSessionStatus status = VerificationSessionStatus.PENDING;

    @Column(name = "current_step_number")
    @Builder.Default
    private int currentStepNumber = 0;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private String metadata = "{}";

    @OneToMany(mappedBy = "session", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<VerificationStepResult> stepResults = new ArrayList<>();

    @OneToMany(mappedBy = "session", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<VerificationDocument> documents = new ArrayList<>();

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    public void start() {
        this.status = VerificationSessionStatus.IN_PROGRESS;
        this.startedAt = Instant.now();
    }

    public void markCompleted() {
        this.status = VerificationSessionStatus.COMPLETED;
        this.completedAt = Instant.now();
    }

    public void markFailed() {
        this.status = VerificationSessionStatus.FAILED;
        this.completedAt = Instant.now();
    }

    public void markExpired() {
        this.status = VerificationSessionStatus.EXPIRED;
    }

    public void cancel() {
        this.status = VerificationSessionStatus.CANCELLED;
        this.completedAt = Instant.now();
    }

    public void advanceStep() {
        this.currentStepNumber++;
    }

    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public boolean isTerminal() {
        return status == VerificationSessionStatus.COMPLETED
                || status == VerificationSessionStatus.FAILED
                || status == VerificationSessionStatus.EXPIRED
                || status == VerificationSessionStatus.CANCELLED;
    }
}
