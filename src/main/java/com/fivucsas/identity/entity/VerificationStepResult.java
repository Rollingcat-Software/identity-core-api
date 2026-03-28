package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.VerificationStepStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "verification_step_results")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class VerificationStepResult {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id", nullable = false)
    private VerificationSession session;

    @Column(name = "step_number", nullable = false)
    private int stepNumber;

    @Column(name = "step_type", nullable = false, length = 30)
    private String stepType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private VerificationStepStatus status = VerificationStepStatus.PENDING;

    @Column(name = "confidence")
    private Double confidence;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "result_data", columnDefinition = "jsonb")
    @Builder.Default
    private String resultData = "{}";

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    public void markInProgress() {
        this.status = VerificationStepStatus.IN_PROGRESS;
        this.startedAt = Instant.now();
    }

    public void markCompleted(Double confidence, String resultData) {
        this.status = VerificationStepStatus.COMPLETED;
        this.confidence = confidence;
        this.resultData = resultData != null ? resultData : "{}";
        this.completedAt = Instant.now();
    }

    public void markFailed(String errorMessage) {
        this.status = VerificationStepStatus.FAILED;
        this.errorMessage = errorMessage;
        this.completedAt = Instant.now();
    }

    public void skip() {
        this.status = VerificationStepStatus.SKIPPED;
        this.completedAt = Instant.now();
    }
}
