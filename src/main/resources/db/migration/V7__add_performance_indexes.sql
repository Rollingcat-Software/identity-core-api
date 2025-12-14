-- V7: Add Performance Indexes
-- Optimizes frequently queried columns for improved query performance
-- These indexes support common access patterns and reduce query latency

-- Users table indexes
-- Unique index for email lookups (login, registration validation)
-- Rollback: DROP INDEX idx_users_email_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique
    ON users (email)
    WHERE deleted_at IS NULL;

COMMENT ON INDEX idx_users_email_unique IS 'Ensures email uniqueness and accelerates login queries';

-- Composite index for tenant-scoped user status queries
-- Supports filtering users by tenant and status (active, locked, etc.)
-- Rollback: DROP INDEX idx_users_tenant_status;
CREATE INDEX IF NOT EXISTS idx_users_tenant_status
    ON users (tenant_id, is_active, is_locked)
    WHERE deleted_at IS NULL;

COMMENT ON INDEX idx_users_tenant_status IS 'Optimizes tenant user listing and status filtering';

-- Biometric data indexes
-- Composite index for user-tenant biometric lookups
-- Ensures data isolation and fast retrieval for biometric operations
-- Rollback: DROP INDEX idx_biometric_user_tenant;
CREATE INDEX IF NOT EXISTS idx_biometric_user_tenant
    ON biometric_data (user_id, tenant_id)
    WHERE deleted_at IS NULL AND is_active = TRUE;

COMMENT ON INDEX idx_biometric_user_tenant IS 'Accelerates biometric data retrieval with tenant isolation';

-- Partial index for primary biometric selection
-- Rollback: DROP INDEX idx_biometric_primary_lookup;
CREATE INDEX IF NOT EXISTS idx_biometric_primary_lookup
    ON biometric_data (user_id, biometric_type)
    WHERE is_primary = TRUE AND deleted_at IS NULL;

COMMENT ON INDEX idx_biometric_primary_lookup IS 'Fast lookup of primary biometric for each type';

-- Audit logs indexes
-- Composite index for tenant audit log queries with time-based filtering
-- Critical for compliance reporting and audit trail analysis
-- Rollback: DROP INDEX idx_audit_tenant_created;
CREATE INDEX IF NOT EXISTS idx_audit_tenant_created
    ON audit_logs (tenant_id, created_at DESC)
    WHERE tenant_id IS NOT NULL;

COMMENT ON INDEX idx_audit_tenant_created IS 'Optimizes tenant audit log queries with time-based pagination';

-- Composite index for user activity tracking
-- Supports user-specific audit queries filtered by action type
-- Rollback: DROP INDEX idx_audit_user_action;
CREATE INDEX IF NOT EXISTS idx_audit_user_action
    ON audit_logs (user_id, action, created_at DESC)
    WHERE user_id IS NOT NULL;

COMMENT ON INDEX idx_audit_user_action IS 'Enables fast user activity history retrieval';

-- Partial index for failed operations
-- Supports security monitoring and incident investigation
-- Rollback: DROP INDEX idx_audit_failed_operations;
CREATE INDEX IF NOT EXISTS idx_audit_failed_operations
    ON audit_logs (tenant_id, action, created_at DESC)
    WHERE success = FALSE;

COMMENT ON INDEX idx_audit_failed_operations IS 'Identifies failed operations for security monitoring';

-- Active sessions indexes
-- Composite index for user session lookups with expiration check
-- Supports session cleanup and validation
-- Rollback: DROP INDEX idx_sessions_user_expires;
CREATE INDEX IF NOT EXISTS idx_sessions_user_expires
    ON active_sessions (user_id, expires_at DESC)
    WHERE is_active = TRUE;

COMMENT ON INDEX idx_sessions_user_expires IS 'Optimizes session validation and cleanup operations';

-- Partial index for expired session cleanup
-- Rollback: DROP INDEX idx_sessions_expired;
CREATE INDEX IF NOT EXISTS idx_sessions_expired
    ON active_sessions (expires_at)
    WHERE is_active = TRUE AND expires_at < CURRENT_TIMESTAMP;

COMMENT ON INDEX idx_sessions_expired IS 'Accelerates expired session cleanup tasks';

-- Refresh tokens indexes
-- Index for token hash lookups during token refresh
-- Already exists in V5/V6, adding if not exists for safety
-- Rollback: DROP INDEX idx_refresh_tokens_hash_lookup;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash_lookup
    ON refresh_tokens (token_hash)
    WHERE is_revoked = FALSE;

COMMENT ON INDEX idx_refresh_tokens_hash_lookup IS 'Fast token validation during refresh operations';

-- Composite index for user token cleanup
-- Supports periodic cleanup of expired tokens per user
-- Rollback: DROP INDEX idx_refresh_tokens_user_expires;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_expires
    ON refresh_tokens (user_id, expires_at)
    WHERE is_revoked = FALSE;

COMMENT ON INDEX idx_refresh_tokens_user_expires IS 'Enables efficient token cleanup per user';

-- Partial index for expired token cleanup
-- Rollback: DROP INDEX idx_refresh_tokens_expired;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expired
    ON refresh_tokens (expires_at)
    WHERE is_revoked = FALSE AND expires_at < CURRENT_TIMESTAMP;

COMMENT ON INDEX idx_refresh_tokens_expired IS 'Identifies expired tokens for cleanup';

-- Security events indexes
-- Composite index for tenant security monitoring
-- Rollback: DROP INDEX idx_security_events_tenant_severity;
CREATE INDEX IF NOT EXISTS idx_security_events_tenant_severity
    ON security_events (tenant_id, severity, created_at DESC)
    WHERE resolved = FALSE;

COMMENT ON INDEX idx_security_events_tenant_severity IS 'Supports real-time security event monitoring';

-- Index for unresolved critical events
-- Rollback: DROP INDEX idx_security_events_critical;
CREATE INDEX IF NOT EXISTS idx_security_events_critical
    ON security_events (severity, created_at DESC)
    WHERE resolved = FALSE AND severity IN ('HIGH', 'CRITICAL');

COMMENT ON INDEX idx_security_events_critical IS 'Fast retrieval of critical unresolved security events';

-- Liveness attempts indexes
-- Composite index for user liveness history
-- Rollback: DROP INDEX idx_liveness_user_tenant_time;
CREATE INDEX IF NOT EXISTS idx_liveness_user_tenant_time
    ON liveness_attempts (user_id, tenant_id, attempted_at DESC);

COMMENT ON INDEX idx_liveness_user_tenant_time IS 'Tracks user liveness attempt history';

-- Biometric verification logs indexes
-- Composite index for verification audit trail
-- Rollback: DROP INDEX idx_verification_user_time;
CREATE INDEX IF NOT EXISTS idx_verification_user_time
    ON biometric_verification_logs (user_id, verified_at DESC);

COMMENT ON INDEX idx_verification_user_time IS 'Audit trail for biometric verification attempts';

-- Password history indexes
-- Index to check recent password reuse
-- Rollback: DROP INDEX idx_password_history_user_recent;
CREATE INDEX IF NOT EXISTS idx_password_history_user_recent
    ON password_history (user_id, created_at DESC);

COMMENT ON INDEX idx_password_history_user_recent IS 'Prevents password reuse by checking history';
