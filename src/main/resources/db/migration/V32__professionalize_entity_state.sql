-- V32: Professionalize entity state management
-- Add audit timestamps for revocation/expiry across NfcCard, OAuth2Client, VerificationDocument

-- NfcCard: add revokedAt for audit trail
ALTER TABLE nfc_cards ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;
-- Backfill: inactive cards get revokedAt = updatedAt
UPDATE nfc_cards SET revoked_at = updated_at WHERE is_active = false AND revoked_at IS NULL;

-- OAuth2Client: add revokedAt + expiresAt
ALTER TABLE oauth2_clients ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE oauth2_clients ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;

-- VerificationDocument: add verifiedAt
ALTER TABLE verification_documents ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP WITH TIME ZONE;
-- Backfill: verified docs get verifiedAt = createdAt
UPDATE verification_documents SET verified_at = created_at WHERE verified = true AND verified_at IS NULL;
