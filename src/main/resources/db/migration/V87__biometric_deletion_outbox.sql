-- V87: Durable outbox for biometric-template deletion on user delete (GDPR Art. 17 / KVKK).
--
-- Problem: deleting a user in identity-core-api only soft-deleted the users row;
-- the face + voice templates held by biometric-processor (face_embeddings /
-- voice_enrollments, a separate service) were never removed. The optional
-- SoftDeletePurgeJob only cascades identity-DB tables.
--
-- Fix: ManageUserService.deleteUser enqueues one row per biometric method (FACE,
-- VOICE) in the SAME transaction as the soft delete, and SoftDeletePurgeJob
-- enqueues again before a hard purge. BiometricDeletionOutboxWorker drains the
-- table through BiometricServicePort.deleteFace/deleteVoice with capped,
-- exponentially backed-off retries.
--
-- Design notes:
--   * NO foreign key to users: a later hard purge must NOT cascade-delete a
--     still-pending deletion intent (the bio templates would be orphaned).
--   * UNIQUE (user_id, method): user ids are never reused and there is no
--     undelete path, so one row per (user, method) makes enqueue idempotent
--     (INSERT ... ON CONFLICT DO NOTHING) — a purge after a completed delete
--     does not re-issue the bio call.
--   * Not tenant-scoped (no RLS / no Hibernate tenantFilter): this is a system
--     work queue drained by a scheduler with no tenant context. tenant_id is
--     informational (audit / triage only).
-- Additive; reversible by DROP TABLE.

CREATE TABLE IF NOT EXISTS biometric_deletion_outbox (
    id              UUID         PRIMARY KEY,
    user_id         UUID         NOT NULL,
    tenant_id       UUID,
    method          VARCHAR(16)  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts        INTEGER      NOT NULL DEFAULT 0,
    last_error      VARCHAR(1000),
    next_attempt_at TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    CONSTRAINT chk_biometric_deletion_outbox_method CHECK (method IN ('FACE', 'VOICE')),
    CONSTRAINT uq_biometric_deletion_outbox_user_method UNIQUE (user_id, method)
);

-- Worker poll: pending rows ordered by due time.
CREATE INDEX IF NOT EXISTS idx_biometric_deletion_outbox_pending
    ON biometric_deletion_outbox (next_attempt_at, created_at)
    WHERE completed_at IS NULL;

COMMENT ON TABLE biometric_deletion_outbox IS
    'Durable intent to delete a user''s biometric templates (FACE/VOICE) in biometric-processor. '
    'Enqueued with the user soft delete / hard purge; drained by BiometricDeletionOutboxWorker.';
COMMENT ON COLUMN biometric_deletion_outbox.next_attempt_at IS
    'Earliest time the worker retries this row (exponential backoff). NULL = due now.';
COMMENT ON COLUMN biometric_deletion_outbox.completed_at IS
    'Set when bio confirmed deletion or reported nothing enrolled (404). NULL = pending.';
