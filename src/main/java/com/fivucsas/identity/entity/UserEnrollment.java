package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_enrollments")
// Defense-in-depth tenant isolation (P0-1). @FilterDef is global from User.java.
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class UserEnrollment {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * Read-only view of the raw user_id FK. Lets callers surface the owning
     * user's id even when the {@link User} row is soft-deleted (and therefore
     * hidden by {@code @SQLRestriction("deleted_at IS NULL")}), without
     * initializing the lazy proxy. insertable/updatable=false because the
     * {@link #user} association already owns this column.
     */
    @Column(name = "user_id", insertable = false, updatable = false)
    private UUID userId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_method_type", nullable = false, length = 30)
    private AuthMethodType authMethodType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private EnrollmentStatus status = EnrollmentStatus.NOT_ENROLLED;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "enrollment_data", columnDefinition = "jsonb")
    @Builder.Default
    private String enrollmentData = "{}";

    @Column(name = "enrolled_at")
    private Instant enrolledAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    /**
     * Image quality score 0..1 from biometric-processor (e.g., DeepFace face_confidence).
     * NULL until enrollment completes via biometric flow. NUMERIC(5,4) in DB.
     */
    @Column(name = "quality_score", precision = 5, scale = 4)
    private BigDecimal qualityScore;

    /**
     * Liveness score 0..1 from biometric-processor anti-spoof pipeline.
     * NULL until enrollment completes via biometric flow. NUMERIC(5,4) in DB.
     */
    @Column(name = "liveness_score", precision = 5, scale = 4)
    private BigDecimal livenessScore;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    public void startEnrollment() {
        this.status = EnrollmentStatus.PENDING;
    }

    public void completeEnrollment(String enrollmentData) {
        this.status = EnrollmentStatus.ENROLLED;
        this.enrolledAt = Instant.now();
        this.enrollmentData = enrollmentData != null ? enrollmentData : "{}";
    }

    /**
     * Mark enrollment complete and capture quality + liveness scores from the
     * biometric-processor response. Either score may be {@code null} when the
     * underlying method does not produce one (e.g. PASSWORD, EMAIL_OTP) — in
     * that case the corresponding previously-recorded score is PRESERVED, not
     * cleared. This is intentional: the web FACE flow records scores during the
     * /enroll step (which lands on a PENDING row) and only afterwards calls the
     * 2-arg /complete (with null scores). Nulling here would wipe the scores
     * recorded moments earlier — the P1-3 persistence bug. A non-null argument
     * overrides the stored value. The DB CHECK constraint enforces 0..1.
     */
    public void completeEnrollment(String enrollmentData, BigDecimal qualityScore, BigDecimal livenessScore) {
        completeEnrollment(enrollmentData);
        if (qualityScore != null) {
            this.qualityScore = qualityScore;
        }
        if (livenessScore != null) {
            this.livenessScore = livenessScore;
        }
    }

    /**
     * Update biometric scores without changing status / enrolledAt. Used by the
     * best-effort writer that records biometric-processor scores after the
     * enrollment row was already marked ENROLLED via a separate /complete call.
     */
    public void recordScores(BigDecimal qualityScore, BigDecimal livenessScore) {
        if (qualityScore != null) {
            this.qualityScore = qualityScore;
        }
        if (livenessScore != null) {
            this.livenessScore = livenessScore;
        }
    }

    public void failEnrollment() {
        this.status = EnrollmentStatus.FAILED;
    }

    public void revoke() {
        this.status = EnrollmentStatus.REVOKED;
        this.revokedAt = Instant.now();
    }

    public void expire() {
        this.status = EnrollmentStatus.EXPIRED;
    }

    public boolean isEnrolled() {
        return this.status == EnrollmentStatus.ENROLLED;
    }
}
