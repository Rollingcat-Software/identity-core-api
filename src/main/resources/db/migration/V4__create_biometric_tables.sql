-- V4: Create Biometric Data Tables
-- Storage for biometric embeddings and liveness detection results

-- Biometric Types Enum
CREATE TYPE biometric_type AS ENUM ('FACE', 'FINGERPRINT', 'VOICE', 'IRIS');
CREATE TYPE biometric_quality AS ENUM ('EXCELLENT', 'GOOD', 'FAIR', 'POOR');

-- Biometric Data Table
CREATE TABLE IF NOT EXISTS biometric_data
(
    id
    UUID
    PRIMARY
    KEY
    DEFAULT
    uuid_generate_v4
(
),
    user_id UUID NOT NULL REFERENCES users
(
    id
) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants
(
    id
)
  ON DELETE CASCADE,

    -- Biometric information
    biometric_type biometric_type NOT NULL DEFAULT 'FACE',
    embedding vector(512), -- pgvector for face embeddings (using Facenet512 dimension)
    embedding_model VARCHAR
(
    50
) DEFAULT 'VGG-Face',
    embedding_dimension INTEGER DEFAULT 2622 CHECK (embedding_dimension > 0),

    -- Quality metrics
    quality_score FLOAT,
    quality_level biometric_quality,

    -- Liveness detection
    liveness_verified BOOLEAN DEFAULT FALSE,
    liveness_score FLOAT,
    liveness_method VARCHAR
(
    50
) DEFAULT 'BIOMETRIC_PUZZLE',

    -- Original image metadata (not storing actual image for privacy)
    image_width INTEGER,
    image_height INTEGER,
    image_format VARCHAR
(
    10
),
    face_detected_confidence FLOAT,

    -- Status
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_primary BOOLEAN DEFAULT FALSE NOT NULL,

    -- Enrollment details
    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    enrolled_from_ip VARCHAR
(
    45
),
    enrolled_from_device VARCHAR
(
    100
),

    -- Expiration (optional, for temporary access)
    expires_at TIMESTAMP,

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,

    -- Timestamps constraint (none - removed CHECK with subquery as it's not supported)
    CONSTRAINT check_quality_score CHECK (quality_score IS NULL OR (quality_score >= 0 AND quality_score <= 1)),
    CONSTRAINT check_liveness_score CHECK (liveness_score IS NULL OR (liveness_score >= 0 AND liveness_score <= 1))
);

-- Partial unique index for unique biometric per user per type (excluding deleted)
CREATE UNIQUE INDEX uq_biometric_user_tenant_type ON biometric_data (user_id, tenant_id, biometric_type) WHERE deleted_at IS NULL;

-- Liveness Detection Attempts Table
CREATE TABLE IF NOT EXISTS liveness_attempts
(
    id
    UUID
    PRIMARY
    KEY
    DEFAULT
    uuid_generate_v4
(
),
    user_id UUID REFERENCES users
(
    id
) ON DELETE SET NULL,
    tenant_id UUID NOT NULL REFERENCES tenants
(
    id
)
  ON DELETE CASCADE,

    -- Puzzle information
    puzzle_id UUID NOT NULL,
    puzzle_steps JSONB NOT NULL,

    -- Result
    success BOOLEAN NOT NULL,
    steps_completed INTEGER NOT NULL,
    total_steps INTEGER NOT NULL,
    completion_time_seconds FLOAT,

    -- Error information
    error_message TEXT,
    failure_reason VARCHAR
(
    100
),

    -- Client information
    ip_address VARCHAR
(
    45
),
    user_agent TEXT,
    device_info JSONB,

    -- Timestamps
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
    );

-- Biometric Verification Logs Table
CREATE TABLE IF NOT EXISTS biometric_verification_logs
(
    id
    UUID
    PRIMARY
    KEY
    DEFAULT
    uuid_generate_v4
(
),
    user_id UUID REFERENCES users
(
    id
) ON DELETE SET NULL,
    tenant_id UUID NOT NULL REFERENCES tenants
(
    id
)
  ON DELETE CASCADE,
    biometric_data_id UUID REFERENCES biometric_data
(
    id
)
  ON DELETE SET NULL,

    -- Verification details
    verified BOOLEAN NOT NULL,
    confidence_score FLOAT,
    similarity_distance FLOAT,
    threshold_used FLOAT,
    model_used VARCHAR
(
    50
),

    -- Context
    verification_type VARCHAR
(
    50
), -- 'LOGIN', 'DOOR_ACCESS', 'TRANSACTION', etc.
    location VARCHAR
(
    255
),
    device_id VARCHAR
(
    100
),

    -- Result
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR
(
    100
),

    -- Client information
    ip_address VARCHAR
(
    45
),
    user_agent TEXT,

    -- Performance
    processing_time_ms INTEGER,

    -- Timestamps
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
    );

-- Indexes for performance
CREATE INDEX idx_biometric_user ON biometric_data (user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_biometric_tenant ON biometric_data (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_biometric_type ON biometric_data (biometric_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_biometric_active ON biometric_data (is_active) WHERE deleted_at IS NULL;
CREATE INDEX idx_biometric_primary ON biometric_data (user_id, is_primary) WHERE is_primary = TRUE AND deleted_at IS NULL;

-- Vector similarity search index (VERY IMPORTANT for performance)
-- IVFFlat index for approximate nearest neighbor search
CREATE INDEX idx_biometric_embedding_ivfflat
    ON biometric_data
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100)
    WHERE deleted_at IS NULL AND is_active = TRUE;

-- Alternative: HNSW index (more accurate but uses more memory)
-- CREATE INDEX idx_biometric_embedding_hnsw
-- ON biometric_data
-- USING hnsw (embedding vector_cosine_ops)
-- WHERE deleted_at IS NULL AND is_active = TRUE;

-- Liveness attempts indexes
CREATE INDEX idx_liveness_user ON liveness_attempts (user_id);
CREATE INDEX idx_liveness_tenant ON liveness_attempts (tenant_id);
CREATE INDEX idx_liveness_puzzle ON liveness_attempts (puzzle_id);
CREATE INDEX idx_liveness_attempted_at ON liveness_attempts (attempted_at DESC);
CREATE INDEX idx_liveness_success ON liveness_attempts (success);

-- Verification logs indexes
CREATE INDEX idx_verification_user ON biometric_verification_logs (user_id);
CREATE INDEX idx_verification_tenant ON biometric_verification_logs (tenant_id);
CREATE INDEX idx_verification_biometric ON biometric_verification_logs (biometric_data_id);
CREATE INDEX idx_verification_verified_at ON biometric_verification_logs (verified_at DESC);
CREATE INDEX idx_verification_success ON biometric_verification_logs (success);

-- Comments
COMMENT
ON TABLE biometric_data IS 'Encrypted biometric embeddings for users';
COMMENT
ON COLUMN biometric_data.embedding IS 'pgvector embedding (flexible dimensions: VGG-Face=2622, Facenet512=512)';
COMMENT
ON COLUMN biometric_data.embedding_dimension IS 'Dimension of the embedding vector (varies by model)';
COMMENT
ON COLUMN biometric_data.liveness_verified IS 'Whether liveness was checked during enrollment';
COMMENT
ON TABLE liveness_attempts IS 'Log of all liveness detection attempts';
COMMENT
ON TABLE biometric_verification_logs IS 'Audit log of biometric verification attempts';

-- Triggers
CREATE TRIGGER update_biometric_data_updated_at
    BEFORE UPDATE
    ON biometric_data
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to ensure only one primary biometric per user per type
CREATE
OR REPLACE FUNCTION ensure_single_primary_biometric()
RETURNS TRIGGER AS $$
BEGIN
    IF
NEW.is_primary = TRUE THEN
UPDATE biometric_data
SET is_primary = FALSE
WHERE user_id = NEW.user_id
  AND biometric_type = NEW.biometric_type
  AND id != NEW.id
          AND deleted_at IS NULL;
END IF;
RETURN NEW;
END;
$$
LANGUAGE plpgsql;

CREATE TRIGGER trg_ensure_single_primary_biometric
    BEFORE INSERT OR
UPDATE ON biometric_data
    FOR EACH ROW
    WHEN (NEW.is_primary = TRUE)
    EXECUTE FUNCTION ensure_single_primary_biometric();
