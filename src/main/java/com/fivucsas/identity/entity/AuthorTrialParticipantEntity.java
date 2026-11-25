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
 * Row of {@code author_trial_participants} (V90): one pseudonymous trial code
 * bound to one pre-created account in the dedicated trial tenant. The code is
 * the only participant identity that reaches the page or the export; the name
 * mapping is kept offline.
 */
@Entity
@Table(name = "author_trial_participants")
@Getter
@Setter
@NoArgsConstructor
public class AuthorTrialParticipantEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "participant_code", nullable = false, length = 16)
    private String participantCode;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    /** Set by the trial enroll endpoint after face + PUZZLE enrollment. */
    @Column(name = "enrolled_at")
    private Instant enrolledAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}