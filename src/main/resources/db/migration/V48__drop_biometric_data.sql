-- V48: Drop the legacy biometric_data table.
--
-- Rationale:
--   * Replaced by user_enrollments (status + V47 quality_score/liveness_score) and
--     biometric-processor's pgvector store (face_embeddings, voice_enrollments) for the
--     embedding payload itself.
--   * Production has 0 rows in biometric_data — the table has been empty since the new
--     pipeline rolled out (verified 2026-04-26 prior to this migration).
--   * The Java entity, JPA repository, and the legacy `service.BiometricService` were dead
--     code (no autowirers reached the entity from any active code path); they are removed
--     in the same change set as this migration.
--
-- Safety:
--   * biometric_verification_logs has FK biometric_data_id with ON DELETE SET NULL, so
--     CASCADE is safe — the dependent rows will keep their other columns and just lose
--     the dangling reference (the verification logs themselves remain intact).
--   * No code reads biometric_data anymore (verified by `grep -rE "biometric_data" src/`).

DROP TABLE IF EXISTS biometric_data CASCADE;

-- The biometric_type and biometric_quality enums were created alongside the table in V4.
-- Drop each one only if no other column still references it (defensive: there should be none).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE udt_name = 'biometric_type'
    ) THEN
        DROP TYPE IF EXISTS biometric_type;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE udt_name = 'biometric_quality'
    ) THEN
        DROP TYPE IF EXISTS biometric_quality;
    END IF;
END $$;
