-- V90: Authors-only trial mode for Paper B (BPCER/APCER measurement).
--
-- One dedicated test tenant holds a handful of pre-created, pseudonymous accounts
-- (author_trial_participants maps P1..P4 to a user id; the name mapping is kept
-- offline). The trial page creates a REAL PUZZLE MFA session for the target
-- account, drives the real Puzzle + face-identity step and the decision is
-- recorded server-side in author_trial_attempts. author_trial_plan_entries holds
-- the server-side shuffled round plan (each round contains every configured
-- challenge exactly once).
--
-- Design notes:
--   * No image, video, audio or template is stored here: only decisions, plan
--     slots, device/environment scalars and version pins.
--   * The tables are tenant-scoped by tenant_id (no Hibernate tenantFilter: the
--     trial surface is reached without a dashboard login and the access key +
--     tenant allow-list are the gate).
--   * attempt_id on a plan slot is set when the slot is claimed; a pending slot
--     is never reused within a round.
-- Additive; reversible with scripts/author-trial-purge.sql (which also
-- soft-deletes the bound users and enqueues their biometric deletion).

CREATE TABLE IF NOT EXISTS author_trial_participants (
    id               UUID         PRIMARY KEY,
    tenant_id        UUID         NOT NULL,
    participant_code VARCHAR(16)  NOT NULL,
    user_id          UUID         NOT NULL,
    enrolled_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_author_trial_participant_code UNIQUE (tenant_id, participant_code),
    CONSTRAINT uq_author_trial_participant_user UNIQUE (user_id)
);

CREATE INDEX IF NOT EXISTS idx_author_trial_participants_tenant
    ON author_trial_participants (tenant_id);

CREATE TABLE IF NOT EXISTS author_trial_plan_entries (
    id               UUID         PRIMARY KEY,
    tenant_id        UUID         NOT NULL,
    participant_code VARCHAR(16)  NOT NULL,
    mode             VARCHAR(8)   NOT NULL,
    round_no         INTEGER      NOT NULL,
    position         INTEGER      NOT NULL,
    challenge        VARCHAR(40)  NOT NULL,
    attempt_id       UUID,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_author_trial_plan_slot UNIQUE (tenant_id, participant_code, mode, round_no, position),
    CONSTRAINT chk_author_trial_plan_mode CHECK (mode IN ('genuine', 'attack')),
    CONSTRAINT chk_author_trial_plan_round CHECK (round_no >= 1),
    CONSTRAINT chk_author_trial_plan_position CHECK (position >= 1)
);

-- Claim query: first free slot in round/position order.
CREATE INDEX IF NOT EXISTS idx_author_trial_plan_free
    ON author_trial_plan_entries (tenant_id, participant_code, mode, round_no, position)
    WHERE attempt_id IS NULL;

CREATE TABLE IF NOT EXISTS author_trial_attempts (
    id                      UUID         PRIMARY KEY,
    tenant_id               UUID         NOT NULL,
    participant_code        VARCHAR(16)  NOT NULL,
    mode                    VARCHAR(8)   NOT NULL,
    target_code             VARCHAR(16)  NOT NULL,
    instrument              VARCHAR(160),
    instrument_preset       VARCHAR(40),
    planned_challenge       VARCHAR(40)  NOT NULL,
    challenge               VARCHAR(40)  NOT NULL,
    round_no                INTEGER      NOT NULL,
    position                INTEGER      NOT NULL,
    plan_entry_id           UUID,
    binding                 BOOLEAN      NOT NULL DEFAULT TRUE,
    difficulty              VARCHAR(16)  NOT NULL DEFAULT 'easy',
    challenge_count         INTEGER      NOT NULL DEFAULT 1,
    liveness_mode           VARCHAR(16),
    trace_contract          VARCHAR(8),
    mfa_session_id          UUID,
    puzzle_session_id       VARCHAR(64),
    started_at              TIMESTAMPTZ  NOT NULL,
    decided_at              TIMESTAMPTZ,
    outcome                 VARCHAR(16),
    liveness_verdict        VARCHAR(8),
    identity_verdict        VARCHAR(8),
    step_outcome            VARCHAR(8),
    failure_reason          VARCHAR(200),
    identity_score          DOUBLE PRECISION,
    identity_distance       DOUBLE PRECISION,
    identity_threshold      DOUBLE PRECISION,
    client_latency_ms       INTEGER,
    challenges_submitted    INTEGER      NOT NULL DEFAULT 0,
    last_challenge_verdict  VARCHAR(8),
    last_challenge_reason   VARCHAR(80),
    device_json             JSONB,
    env_json                JSONB,
    web_version             VARCHAR(80),
    api_version             VARCHAR(80),
    bio_version             VARCHAR(80),
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_author_trial_attempt_mode CHECK (mode IN ('genuine', 'attack')),
    CONSTRAINT chk_author_trial_attempt_outcome
        CHECK (outcome IS NULL OR outcome IN ('accept', 'reject', 'error', 'abandoned'))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_author_trial_attempt_mfa
    ON author_trial_attempts (mfa_session_id) WHERE mfa_session_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_author_trial_attempt_puzzle
    ON author_trial_attempts (puzzle_session_id) WHERE puzzle_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_author_trial_attempts_tenant_started
    ON author_trial_attempts (tenant_id, started_at);

COMMENT ON TABLE author_trial_participants IS
    'Paper B authors-only trial: pseudonymous participant code -> pre-created test-tenant account. No name/email here.';
COMMENT ON TABLE author_trial_plan_entries IS
    'Paper B trial round plan: each round is a random permutation of the configured PUZZLE challenges; a slot is claimed by one attempt.';
COMMENT ON TABLE author_trial_attempts IS
    'Paper B trial attempt log: server-recorded decision, plan slot, device/environment scalars and version pins. No media, no template.';