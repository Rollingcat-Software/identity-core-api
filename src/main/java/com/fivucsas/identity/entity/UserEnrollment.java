package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_enrollments")
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
