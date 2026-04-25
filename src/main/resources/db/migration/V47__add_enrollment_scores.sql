-- V47: Add quality + liveness score columns to user_enrollments.
--
-- Surfaces biometric-processor scores (DeepFace face_confidence, liveness
-- anti-spoof verdict) on the enrollment row so the admin Enrollments table
-- can display them. NULL until the enrollment completes; old rows stay NULL
-- (no synthetic backfill — frontend renders "-" for nulls).
--
-- Idempotent (ADD COLUMN IF NOT EXISTS) so re-runs on already-migrated DBs
-- are safe.
ALTER TABLE user_enrollments
    ADD COLUMN IF NOT EXISTS quality_score NUMERIC(5,4)
        CHECK (quality_score IS NULL OR (quality_score >= 0 AND quality_score <= 1)),
    ADD COLUMN IF NOT EXISTS liveness_score NUMERIC(5,4)
        CHECK (liveness_score IS NULL OR (liveness_score >= 0 AND liveness_score <= 1));

COMMENT ON COLUMN user_enrollments.quality_score IS
    'Image quality 0..1 from biometric-processor (e.g., DeepFace face_confidence). NULL until enrollment completes.';
COMMENT ON COLUMN user_enrollments.liveness_score IS
    'Liveness 0..1 from biometric-processor anti-spoof pipeline. NULL until enrollment completes.';
