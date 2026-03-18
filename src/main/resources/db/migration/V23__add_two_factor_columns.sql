-- V23: Add 2FA persistence columns to users table
-- Previously these were @Transient fields, meaning 2FA state was lost on entity detach.

ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_secret VARCHAR(512);
ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_backup_codes VARCHAR(1024);
