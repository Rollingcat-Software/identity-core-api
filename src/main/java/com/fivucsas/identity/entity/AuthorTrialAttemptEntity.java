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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/**
 * Row of {@code author_trial_attempts} (V90): one server-recorded trial attempt.
 *
 * <p>The decision fields ({@code outcome}, verdicts, score, reason) are written
 * by the real MFA machinery ({@code PuzzleVerifyMfaStepHandler} /
 * {@code VerifyMfaStepService}); the page only supplies the plan slot metadata
 * at session creation and a technical finish status. No image, video, audio or
 * template is stored.
 */
@Entity
@Table(name = "author_trial_attempts")
@Getter
@Setter
@NoArgsConstructor
public class AuthorTrialAttemptEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    /** The author who performed the attempt (operator). */
    @Column(name = "participant_code", nullable = false, length = 16)
    private String participantCode;

    @Column(name = "mode", nullable = false, length = 8)
    private String mode;

    /** The account whose template was checked (victim; equals participant for genuine). */
    @Column(name = "target_code", nullable = false, length = 16)
    private String targetCode;

    @Column(name = "instrument", length = 160)
    private String instrument;

    @Column(name = "instrument_preset", length = 40)
    private String instrumentPreset;

    @Column(name = "planned_challenge", nullable = false, length = 40)
    private String plannedChallenge;

    /** The action bio actually issued (normally equals plannedChallenge). */
    @Column(name = "challenge", nullable = false, length = 40)
    private String challenge;

    @Column(name = "round_no", nullable = false)
    private int roundNo;

    @Column(name = "position", nullable = false)
    private int position;

    @Column(name = "plan_entry_id")
    private UUID planEntryId;

    @Column(name = "binding", nullable = false)
    private boolean binding;

    @Column(name = "difficulty", nullable = false, length = 16)
    private String difficulty;

    @Column(name = "challenge_count", nullable = false)
    private int challengeCount;

    @Column(name = "liveness_mode", length = 16)
    private String livenessMode;

    @Column(name = "trace_contract", length = 8)
    private String traceContract;

    @Column(name = "mfa_session_id")
    private UUID mfaSessionId;

    @Column(name = "puzzle_session_id", length = 64)
    private String puzzleSessionId;

    @Column(name = "started_at", nullable = false)
    private Instant startedAt;

    @Column(name = "decided_at")
    private Instant decidedAt;

    @Column(name = "outcome", length = 16)
    private String outcome;

    @Column(name = "liveness_verdict", length = 8)
    private String livenessVerdict;

    @Column(name = "identity_verdict", length = 8)
    private String identityVerdict;

    @Column(name = "step_outcome", length = 8)
    private String stepOutcome;

    @Column(name = "failure_reason", length = 200)
    private String failureReason;

    @Column(name = "identity_score")
    private Double identityScore;

    @Column(name = "identity_distance")
    private Double identityDistance;

    @Column(name = "identity_threshold")
    private Double identityThreshold;

    @Column(name = "client_latency_ms")
    private Integer clientLatencyMs;

    @Column(name = "challenges_submitted", nullable = false)
    private int challengesSubmitted;

    @Column(name = "last_challenge_verdict", length = 8)
    private String lastChallengeVerdict;

    @Column(name = "last_challenge_reason", length = 80)
    private String lastChallengeReason;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "device_json", columnDefinition = "jsonb")
    private String deviceJson;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "env_json", columnDefinition = "jsonb")
    private String envJson;

    @Column(name = "web_version", length = 80)
    private String webVersion;

    @Column(name = "api_version", length = 80)
    private String apiVersion;

    @Column(name = "bio_version", length = 80)
    private String bioVersion;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}