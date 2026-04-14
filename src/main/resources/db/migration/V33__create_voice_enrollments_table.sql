-- V33: Create voice_enrollments table
-- Stores speaker embeddings for voice authentication
-- Pattern matches face_embeddings table: INDIVIDUAL rows + CENTROID row per user
-- Uses Resemblyzer GE2E 256-dimensional embeddings

CREATE TABLE IF NOT EXISTS voice_enrollments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255),
    embedding vector(256) NOT NULL,
    quality_score FLOAT NOT NULL CHECK (quality_score >= 0.0 AND quality_score <= 1.0),
    enrollment_type VARCHAR(50) NOT NULL CHECK (enrollment_type IN ('INDIVIDUAL', 'CENTROID')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Ensure only one CENTROID per user per tenant
CREATE UNIQUE INDEX IF NOT EXISTS uq_voice_centroid
    ON voice_enrollments(user_id, COALESCE(tenant_id, ''))
    WHERE enrollment_type = 'CENTROID' AND deleted_at IS NULL;

-- Fast lookup by user
CREATE INDEX IF NOT EXISTS idx_voice_enrollments_user_id
    ON voice_enrollments(user_id)
    WHERE deleted_at IS NULL;

-- Fast lookup by type (for centroid queries)
CREATE INDEX IF NOT EXISTS idx_voice_enrollments_type
    ON voice_enrollments(enrollment_type);

-- pgvector IVFFlat index for 1:N search
-- 256 dimensions (Resemblyzer GE2E output)
-- lists=100 is appropriate for <1M rows
CREATE INDEX IF NOT EXISTS idx_voice_embeddings_ivfflat
    ON voice_enrollments USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
