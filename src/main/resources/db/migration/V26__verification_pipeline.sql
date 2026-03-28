-- V26: Verification Pipeline
-- Extends auth flow system to support identity verification workflows
-- Adds verification sessions, step results, and document tracking

-- ============================================================================
-- Extend auth_flows with flow_type and industry_template
-- ============================================================================
ALTER TABLE auth_flows ADD COLUMN IF NOT EXISTS flow_type VARCHAR(30) DEFAULT 'AUTHENTICATION' NOT NULL;
ALTER TABLE auth_flows ADD COLUMN IF NOT EXISTS industry_template VARCHAR(50);

-- ============================================================================
-- Extend auth_methods type constraint for verification step types
-- ============================================================================
ALTER TABLE auth_methods DROP CONSTRAINT IF EXISTS chk_auth_method_type;
ALTER TABLE auth_methods ADD CONSTRAINT chk_auth_method_type
    CHECK (type IN (
        'PASSWORD','EMAIL_OTP','SMS_OTP','TOTP','QR_CODE','FACE','FINGERPRINT','VOICE','NFC_DOCUMENT','HARDWARE_KEY',
        'DOCUMENT_SCAN','NFC_CHIP_READ','DATA_EXTRACT','FACE_MATCH','LIVENESS_CHECK',
        'ADDRESS_PROOF','WATCHLIST_CHECK','AGE_VERIFICATION','PHONE_VERIFICATION'
    ));

-- ============================================================================
-- Seed verification-specific auth methods
-- ============================================================================
INSERT INTO auth_methods (type, name, description, category, platforms, requires_enrollment, is_active) VALUES
    ('DOCUMENT_SCAN',      'Document Scan',      'Capture and detect ID document type',            'PREMIUM',    '{WEB,ANDROID,IOS}',         false, true),
    ('NFC_CHIP_READ',      'NFC Chip Read',      'Read NFC chip from identity document',           'ENTERPRISE', '{ANDROID,IOS}',             false, true),
    ('DATA_EXTRACT',       'Data Extract',        'Extract personal data from document via OCR',    'PREMIUM',    '{WEB,ANDROID,IOS}',         false, true),
    ('FACE_MATCH',         'Face Match',          'Compare live face against document photo',       'PREMIUM',    '{WEB,ANDROID,IOS,DESKTOP}', false, true),
    ('LIVENESS_CHECK',     'Liveness Check',      'Verify person is physically present',            'PREMIUM',    '{WEB,ANDROID,IOS,DESKTOP}', false, true),
    ('ADDRESS_PROOF',      'Address Proof',       'Verify residential address',                     'STANDARD',   '{WEB,ANDROID,IOS,DESKTOP}', false, true),
    ('WATCHLIST_CHECK',    'Watchlist Check',     'Screen against sanctions and PEP lists',         'ENTERPRISE', '{WEB,ANDROID,IOS,DESKTOP}', false, true),
    ('AGE_VERIFICATION',   'Age Verification',    'Verify minimum age requirement',                 'STANDARD',   '{WEB,ANDROID,IOS,DESKTOP}', false, true),
    ('PHONE_VERIFICATION', 'Phone Verification',  'Verify phone number ownership via OTP',          'BASIC',      '{WEB,ANDROID,IOS,DESKTOP}', false, true)
ON CONFLICT (type) DO NOTHING;

-- ============================================================================
-- TABLE: verification_sessions (tracks pipeline execution)
-- ============================================================================
CREATE TABLE IF NOT EXISTS verification_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID           NOT NULL REFERENCES users(id),
    tenant_id           UUID           NOT NULL REFERENCES tenants(id),
    flow_id             UUID           NOT NULL REFERENCES auth_flows(id),
    status              VARCHAR(30)    NOT NULL DEFAULT 'PENDING',
    current_step_number INTEGER        DEFAULT 0,
    started_at          TIMESTAMP WITH TIME ZONE,
    completed_at        TIMESTAMP WITH TIME ZONE,
    expires_at          TIMESTAMP WITH TIME ZONE,
    metadata            JSONB          DEFAULT '{}',
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

DO $$ BEGIN
    ALTER TABLE verification_sessions ADD CONSTRAINT chk_verification_session_status
        CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','FAILED','EXPIRED','CANCELLED'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_verification_sessions_user ON verification_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_verification_sessions_tenant ON verification_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_verification_sessions_status ON verification_sessions(status);

-- ============================================================================
-- TABLE: verification_step_results (per-step outcome within a verification session)
-- ============================================================================
CREATE TABLE IF NOT EXISTS verification_step_results (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          UUID           NOT NULL REFERENCES verification_sessions(id) ON DELETE CASCADE,
    step_number         INTEGER        NOT NULL,
    step_type           VARCHAR(30)    NOT NULL,
    status              VARCHAR(20)    NOT NULL DEFAULT 'PENDING',
    confidence          DOUBLE PRECISION,
    result_data         JSONB          DEFAULT '{}',
    error_message       TEXT,
    started_at          TIMESTAMP WITH TIME ZONE,
    completed_at        TIMESTAMP WITH TIME ZONE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

DO $$ BEGIN
    ALTER TABLE verification_step_results ADD CONSTRAINT chk_step_result_status
        CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','FAILED','SKIPPED'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_verification_step_results_session ON verification_step_results(session_id);

-- ============================================================================
-- TABLE: verification_documents (scanned document metadata)
-- ============================================================================
CREATE TABLE IF NOT EXISTS verification_documents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          UUID           NOT NULL REFERENCES verification_sessions(id) ON DELETE CASCADE,
    user_id             UUID           NOT NULL REFERENCES users(id),
    document_type       VARCHAR(30)    NOT NULL,
    document_number     VARCHAR(50),
    holder_name         VARCHAR(200),
    date_of_birth       DATE,
    expiry_date         DATE,
    nationality         VARCHAR(5),
    mrz_data            TEXT,
    face_image_hash     VARCHAR(64),
    verified            BOOLEAN        DEFAULT FALSE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verification_documents_user ON verification_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_verification_documents_session ON verification_documents(session_id);

-- ============================================================================
-- Extend users table with identity verification fields
-- ============================================================================
ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_verified_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_level VARCHAR(20) DEFAULT 'NONE';

-- ============================================================================
-- SEED: verification permissions
-- ============================================================================
INSERT INTO permissions (name, description, resource, action) VALUES
    ('verification:read',    'Read verification sessions',   'verification', 'read'),
    ('verification:create',  'Create verification sessions', 'verification', 'create'),
    ('verification:update',  'Update verification sessions', 'verification', 'update')
ON CONFLICT (name) DO NOTHING;
