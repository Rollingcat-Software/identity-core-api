-- V14: Fix User Settings Schema
-- Aligns user_settings table with UserSettings entity
-- Issue: V11 was modified after deployment, production has different schema

-- ============================================================================
-- 1. Add missing columns
-- ============================================================================

-- Add settings column (JSONB) if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'user_settings' AND column_name = 'settings') THEN
        ALTER TABLE user_settings ADD COLUMN settings JSONB NOT NULL DEFAULT '{}';
    END IF;
END $$;

-- Add updated_at column if it doesn't exist
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL;

-- ============================================================================
-- 2. Migrate data from old columns to settings JSONB (only if old columns exist)
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'user_settings' AND column_name = 'notifications_enabled') THEN

        UPDATE user_settings
        SET settings = jsonb_build_object(
            'notifications', jsonb_build_object(
                'email', COALESCE(notifications_enabled, true),
                'push', true,
                'securityAlerts', true
            ),
            'security', jsonb_build_object(
                'twoFactorEnabled', false,
                'sessionTimeout', 30
            ),
            'appearance', jsonb_build_object(
                'theme', COALESCE(LOWER(theme), 'light'),
                'language', COALESCE(language, 'en'),
                'density', 'comfortable'
            )
        ) || COALESCE(settings_json, '{}'::jsonb)
        WHERE settings = '{}' OR settings IS NULL;

    END IF;
END $$;

-- ============================================================================
-- 3. Drop old columns (no longer needed)
-- ============================================================================

ALTER TABLE user_settings DROP COLUMN IF EXISTS theme;
ALTER TABLE user_settings DROP COLUMN IF EXISTS language;
ALTER TABLE user_settings DROP COLUMN IF EXISTS notifications_enabled;
ALTER TABLE user_settings DROP COLUMN IF EXISTS settings_json;

-- ============================================================================
-- 4. Ensure constraints
-- ============================================================================

-- Ensure settings column is not null with default
ALTER TABLE user_settings ALTER COLUMN settings SET DEFAULT '{}';
ALTER TABLE user_settings ALTER COLUMN settings SET NOT NULL;

-- ============================================================================
-- 5. Comments
-- ============================================================================

COMMENT ON COLUMN user_settings.settings IS 'All user settings stored as JSONB';
COMMENT ON COLUMN user_settings.updated_at IS 'Last update timestamp';
