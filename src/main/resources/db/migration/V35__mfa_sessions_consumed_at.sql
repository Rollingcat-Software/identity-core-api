-- V35: Add consumed_at column to mfa_sessions for single-use enforcement
--
-- Previously OAuth2Controller.authorizeComplete minted a code and then deleted
-- the session. If the delete failed (DB error, transaction rollback), the
-- completed session remained in the DB and could be replayed for a second
-- authorization code.
--
-- The new flow inside a @Transactional boundary:
--   1. SELECT session by token.
--   2. Verify completed_at IS NOT NULL AND consumed_at IS NULL.
--   3. SET consumed_at = now() BEFORE minting the code.
--   4. Mint code + delete session — all in the same transaction.
--
-- Any failure after step 3 rolls the whole transaction back, including
-- consumed_at. But if the delete itself fails post-commit (impossible given
-- the single TX boundary), the consumed_at check on the next request rejects
-- the replay.

ALTER TABLE mfa_sessions
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;
