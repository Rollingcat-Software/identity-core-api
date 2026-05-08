-- V58: OAuth2 client_secret rotation grace window
-- ---------------------------------------------------------------------------
-- Backs the new POST /api/v1/oauth2/clients/{id}/rotate-secret endpoint.
-- After rotation, the OLD secret remains valid for 24h so deployed
-- integrations can roll over without downtime.
--
-- Schema:
--   previous_secret             — bcrypt hash of the prior client_secret
--   previous_secret_expires_at  — UTC instant after which the prior secret is
--                                 rejected. Cleared (NULL/NULL) on rotation
--                                 if the previous grace window already expired.
--
-- Both columns are NULLABLE — clients that have never been rotated, or whose
-- prior grace window has already lapsed and been compacted, carry NULL/NULL.
--
-- INVESTIGATION_MASTER_2026-05-07 §"developer/tenant constraints":
-- "No client_secret rotation endpoint — operators must delete+recreate
-- clients, breaking active integrations."

ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS previous_secret             VARCHAR(255),
    ADD COLUMN IF NOT EXISTS previous_secret_expires_at  TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN oauth2_clients.previous_secret IS
    'bcrypt hash of the prior client_secret retained during the post-rotation grace window. NULL when no rotation has occurred or the grace window has compacted.';
COMMENT ON COLUMN oauth2_clients.previous_secret_expires_at IS
    'UTC instant after which the previous_secret is rejected. NULL when previous_secret is NULL.';
