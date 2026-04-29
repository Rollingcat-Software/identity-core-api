-- V50: Refresh-token rotation family tracking (Sec-P2 #6, 2026-04-29)
--
-- Background:
--   RFC 6749 §10.4 + OAuth 2.0 Security BCP §4.13: refresh-token rotation
--   alone is not sufficient. An attacker who exfiltrates a token and races
--   the legitimate client can present the captured token. The rotation
--   logic naively revokes whichever token "loses" the race and mints a new
--   one for whoever "wins". Detection requires that a presented but
--   already-revoked token triggers revocation of the entire descendant
--   chain ("token family") — not just the presented token.
--
--   This migration adds a `family_id UUID` column to refresh_tokens. On
--   initial login, a fresh family_id is minted; on rotation, the parent's
--   family_id is propagated to the child. When the application detects a
--   replay of a revoked token, it bulk-revokes every row sharing the same
--   family_id (active or otherwise), forcing the user to re-authenticate.
--
-- This migration is idempotent — re-running it is a no-op.

-- 1) Add the column. NOT NULL is enforced after backfill.
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS family_id UUID;

-- 2) Backfill existing rows. Each pre-existing token forms a trivial
--    1-token family; we use the row's own id as the family_id so the
--    backfill is deterministic and replayable.
UPDATE refresh_tokens
   SET family_id = id
 WHERE family_id IS NULL;

-- 3) Lock the column NOT NULL — the application contract guarantees every
--    new token (whether minted at login or rotated) carries a family_id.
ALTER TABLE refresh_tokens
    ALTER COLUMN family_id SET NOT NULL;

-- 4) Index for the family-bulk-revoke query (`WHERE family_id = ?`).
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id
    ON refresh_tokens (family_id);

COMMENT ON COLUMN refresh_tokens.family_id IS
    'Rotation-family identifier. All tokens minted from a single initial '
    'login share one family_id, propagated through every rotation. '
    'When the application detects replay of a revoked token, every row '
    'with this family_id is revoked at once (RFC 6749 §10.4 + OAuth 2.0 '
    'Security BCP §4.13). See RefreshTokenService.rotateRefreshToken.';
