-- Gap Ü2: SHA-256 (hex) of the face embedding that a PUZZLE step's identity
-- binding matched in this MFA session. A later FACE embedding step counts as
-- backed by that liveness factor only when its embedding has the same digest.
-- Nullable and additive: NULL means no bound PUZZLE in the session. The
-- embedding itself is never stored.
ALTER TABLE mfa_sessions ADD COLUMN liveness_embedding_sha256 VARCHAR(64);
