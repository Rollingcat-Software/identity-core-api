package com.fivucsas.identity.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * Row of {@code author_trial_plan_entries} (V90): one slot of a server-side
 * shuffled round. A round is a random permutation of the configured PUZZLE
 * challenges, so every round contains each challenge exactly once. The slot is
 * claimed by exactly one attempt ({@code attemptId}).
 */
@Entity
@Table(name = "author_trial_plan_entries")
@Getter
@Setter
@NoArgsConstructor
public class AuthorTrialPlanEntryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "participant_code", nullable = false, length = 16)
    private String participantCode;

    @Column(name = "mode", nullable = false, length = 8)
    private String mode;

    @Column(name = "round_no", nullable = false)
    private int roundNo;

    @Column(name = "position", nullable = false)
    private int position;

    @Column(name = "challenge", nullable = false, length = 40)
    private String challenge;

    /** Null until an attempt claims the slot. */
    @Column(name = "attempt_id")
    private UUID attemptId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}