package com.fivucsas.identity.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * Row of {@code biometric_deletion_outbox} (V87): a durable intent to delete a
 * user's FACE or VOICE templates in biometric-processor.
 *
 * <p>Deliberately NOT tenant-filtered and NOT linked to {@code User} by an
 * association/FK: it is a system work queue drained without tenant context,
 * and it must survive the user's hard purge. Writes go through native queries
 * on {@code BiometricDeletionOutboxRepository} (idempotent insert, targeted
 * updates), so this entity is read-only from JPA's point of view.
 */
@Entity
@Table(name = "biometric_deletion_outbox")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class BiometricDeletionOutboxEntry {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "tenant_id")
    private UUID tenantId;

    @Column(name = "method", nullable = false, length = 16)
    private String method;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "last_error", length = 1000)
    private String lastError;

    @Column(name = "next_attempt_at")
    private Instant nextAttemptAt;

    @Column(name = "completed_at")
    private Instant completedAt;
}
