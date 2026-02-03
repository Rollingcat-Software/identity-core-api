-- V12: Fix User Entity Alignment
-- Adds missing columns to align database with Java entity

-- ============================================================================
-- 1. Add Missing User Columns
-- ============================================================================

-- Add address column
ALTER TABLE users ADD COLUMN IF NOT EXISTS address VARCHAR(500);

-- Add id_number column (Turkish TC Kimlik No)
ALTER TABLE users ADD COLUMN IF NOT EXISTS id_number VARCHAR(11);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_id_number
    ON users (id_number)
    WHERE id_number IS NOT NULL AND deleted_at IS NULL;

-- Add user_type column (enum: ROOT, TENANT_ADMIN, TENANT_MEMBER, GUEST)
ALTER TABLE users ADD COLUMN IF NOT EXISTS user_type VARCHAR(20) NOT NULL DEFAULT 'TENANT_MEMBER';
CREATE INDEX IF NOT EXISTS idx_users_user_type
    ON users (user_type)
    WHERE deleted_at IS NULL;

-- Add status column (enum: ACTIVE, INACTIVE, SUSPENDED, PENDING_VERIFICATION)
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';

-- Add expires_at column (for guest users)
ALTER TABLE users ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_users_expires_at
    ON users (expires_at)
    WHERE expires_at IS NOT NULL AND deleted_at IS NULL;

-- Add invited_by column (for guest users)
ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_by UUID REFERENCES users(id);
CREATE INDEX IF NOT EXISTS idx_users_invited_by
    ON users (invited_by)
    WHERE invited_by IS NOT NULL;

-- Add biometric tracking columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_biometric_enrolled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS enrolled_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_count INTEGER DEFAULT 0;

-- ============================================================================
-- 2. Update ROOT user if exists
-- ============================================================================
UPDATE users SET user_type = 'ROOT'
WHERE email = 'admin@fivucsas.local'
  AND user_type = 'TENANT_MEMBER';

-- ============================================================================
-- 3. Comments
-- ============================================================================
COMMENT ON COLUMN users.address IS 'User address (optional)';
COMMENT ON COLUMN users.id_number IS 'Turkish TC Kimlik Number - 11 digits';
COMMENT ON COLUMN users.user_type IS 'User type hierarchy: ROOT > TENANT_ADMIN > TENANT_MEMBER > GUEST';
COMMENT ON COLUMN users.status IS 'Account status: ACTIVE, INACTIVE, SUSPENDED, PENDING_VERIFICATION';
COMMENT ON COLUMN users.expires_at IS 'Account expiration (for GUEST users)';
COMMENT ON COLUMN users.invited_by IS 'User who invited this user (for GUEST users)';
COMMENT ON COLUMN users.is_biometric_enrolled IS 'Whether user has enrolled biometric data';
COMMENT ON COLUMN users.enrolled_at IS 'When biometric data was enrolled';
COMMENT ON COLUMN users.last_verified_at IS 'Last successful biometric verification';
COMMENT ON COLUMN users.verification_count IS 'Total biometric verification count';
