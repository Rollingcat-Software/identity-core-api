-- V8: Add Audit Log Enhancements
-- Extends audit_logs table with additional tracking fields for comprehensive audit trail
-- Supports distributed tracing, performance monitoring, and detailed request context

-- Add new columns to audit_logs table
-- IPv6 support (45 characters for full IPv6 address notation)
-- Rollback: ALTER TABLE audit_logs DROP COLUMN IF EXISTS ip_address_v2;
-- Note: Column already exists from V5, checking schema compatibility
DO $$
BEGIN
    -- Add user_agent if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='audit_logs' AND column_name='user_agent_v2') THEN
        ALTER TABLE audit_logs ADD COLUMN user_agent_v2 TEXT;
        COMMENT ON COLUMN audit_logs.user_agent_v2 IS 'Browser/client user agent string for request identification';
    END IF;

    -- Add request_id for distributed tracing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='audit_logs' AND column_name='request_id') THEN
        ALTER TABLE audit_logs ADD COLUMN request_id UUID;
        COMMENT ON COLUMN audit_logs.request_id IS 'Unique request identifier for distributed tracing across services';
    END IF;

    -- Add duration_ms for performance monitoring
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='audit_logs' AND column_name='duration_ms') THEN
        ALTER TABLE audit_logs ADD COLUMN duration_ms INTEGER CHECK (duration_ms >= 0);
        COMMENT ON COLUMN audit_logs.duration_ms IS 'Operation duration in milliseconds for performance analysis';
    END IF;

    -- Add enhanced metadata column (V5 already has metadata, but ensuring JSONB type)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='audit_logs' AND column_name='enhanced_metadata') THEN
        ALTER TABLE audit_logs ADD COLUMN enhanced_metadata JSONB DEFAULT '{}';
        COMMENT ON COLUMN audit_logs.enhanced_metadata IS 'Flexible JSON storage for custom audit data (correlation IDs, tags, business context)';
    END IF;
END $$;

-- Create index on request_id for distributed tracing
-- Enables fast lookup of all audit logs for a specific request across the system
-- Rollback: DROP INDEX idx_audit_request_id;
CREATE INDEX IF NOT EXISTS idx_audit_request_id
    ON audit_logs (request_id)
    WHERE request_id IS NOT NULL;

COMMENT ON INDEX idx_audit_request_id IS 'Enables distributed request tracing across microservices';

-- Create index on duration_ms for performance monitoring
-- Supports identification of slow operations for optimization
-- Rollback: DROP INDEX idx_audit_duration_slow;
CREATE INDEX IF NOT EXISTS idx_audit_duration_slow
    ON audit_logs (duration_ms DESC, created_at DESC)
    WHERE duration_ms > 1000; -- Only index operations taking more than 1 second

COMMENT ON INDEX idx_audit_duration_slow IS 'Identifies slow operations for performance optimization';

-- Create composite index for request tracing with timing
-- Rollback: DROP INDEX idx_audit_request_timing;
CREATE INDEX IF NOT EXISTS idx_audit_request_timing
    ON audit_logs (request_id, created_at, duration_ms)
    WHERE request_id IS NOT NULL;

COMMENT ON INDEX idx_audit_request_timing IS 'Supports request timeline analysis for debugging';

-- Create GIN index on enhanced_metadata for JSON queries
-- Enables efficient querying of JSON fields for advanced filtering
-- Rollback: DROP INDEX idx_audit_enhanced_metadata_gin;
CREATE INDEX IF NOT EXISTS idx_audit_enhanced_metadata_gin
    ON audit_logs USING GIN (enhanced_metadata)
    WHERE enhanced_metadata IS NOT NULL AND enhanced_metadata != '{}'::jsonb;

COMMENT ON INDEX idx_audit_enhanced_metadata_gin IS 'Enables fast JSON field queries for custom audit attributes';

-- Create function to automatically populate request_id from metadata if present
-- Helps with migration and ensures backward compatibility
CREATE OR REPLACE FUNCTION populate_audit_request_id()
RETURNS TRIGGER AS $$
BEGIN
    -- If request_id is not set but exists in metadata or enhanced_metadata, populate it
    IF NEW.request_id IS NULL THEN
        IF NEW.metadata ? 'request_id' THEN
            NEW.request_id := (NEW.metadata->>'request_id')::UUID;
        ELSIF NEW.enhanced_metadata ? 'request_id' THEN
            NEW.request_id := (NEW.enhanced_metadata->>'request_id')::UUID;
        END IF;
    END IF;

    -- If duration_ms is not set but exists in metadata, populate it
    IF NEW.duration_ms IS NULL THEN
        IF NEW.metadata ? 'duration_ms' THEN
            NEW.duration_ms := (NEW.metadata->>'duration_ms')::INTEGER;
        ELSIF NEW.enhanced_metadata ? 'duration_ms' THEN
            NEW.duration_ms := (NEW.enhanced_metadata->>'duration_ms')::INTEGER;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for automatic request_id population
CREATE TRIGGER trg_populate_audit_request_id
    BEFORE INSERT ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION populate_audit_request_id();

COMMENT ON TRIGGER trg_populate_audit_request_id ON audit_logs IS 'Automatically extracts request_id and duration from metadata for indexing';

-- Create function for audit log data retention policy
-- Implements tiered retention: keep detailed logs for 90 days, summary for 1 year
CREATE OR REPLACE FUNCTION apply_audit_retention_policy()
RETURNS void AS $$
BEGIN
    -- Archive audit logs older than 90 days by removing detailed metadata
    -- Keep core audit trail but reduce storage footprint
    UPDATE audit_logs
    SET enhanced_metadata = '{}'::jsonb,
        old_values = NULL,
        new_values = NULL
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '90 days'
      AND (enhanced_metadata IS NOT NULL OR old_values IS NOT NULL OR new_values IS NOT NULL);

    -- Delete audit logs older than 1 year (already archived elsewhere)
    DELETE FROM audit_logs
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 year';

    RAISE NOTICE 'Audit retention policy applied: archived % rows', FOUND;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION apply_audit_retention_policy() IS 'Implements tiered audit log retention (90 days detailed, 1 year summary)';

-- Create index for retention policy queries
-- Rollback: DROP INDEX idx_audit_retention;
CREATE INDEX IF NOT EXISTS idx_audit_retention
    ON audit_logs (created_at)
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '90 days';

COMMENT ON INDEX idx_audit_retention IS 'Optimizes audit log retention policy execution';

-- Create view for recent audit activity (last 30 days)
-- Provides fast access to recent audit logs without scanning entire table
CREATE OR REPLACE VIEW v_recent_audit_logs AS
SELECT
    id,
    tenant_id,
    user_id,
    action,
    resource_type,
    resource_id,
    http_method,
    endpoint,
    status_code,
    success,
    error_message,
    ip_address,
    user_agent,
    user_agent_v2,
    request_id,
    duration_ms,
    created_at,
    -- Combine metadata for backward compatibility
    COALESCE(enhanced_metadata, '{}'::jsonb) || COALESCE(metadata, '{}'::jsonb) as combined_metadata
FROM audit_logs
WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
ORDER BY created_at DESC;

COMMENT ON VIEW v_recent_audit_logs IS 'Recent audit logs (30 days) for fast access and monitoring';

-- Create view for slow operations (performance monitoring)
CREATE OR REPLACE VIEW v_slow_operations AS
SELECT
    id,
    tenant_id,
    user_id,
    action,
    resource_type,
    endpoint,
    duration_ms,
    created_at,
    request_id
FROM audit_logs
WHERE duration_ms > 1000 -- Operations taking more than 1 second
  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY duration_ms DESC;

COMMENT ON VIEW v_slow_operations IS 'Operations exceeding 1 second in the last 7 days for performance analysis';

-- Create materialized view for audit statistics (refreshed periodically)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_audit_statistics AS
SELECT
    tenant_id,
    action,
    resource_type,
    DATE(created_at) as audit_date,
    COUNT(*) as total_operations,
    COUNT(*) FILTER (WHERE success = TRUE) as successful_operations,
    COUNT(*) FILTER (WHERE success = FALSE) as failed_operations,
    AVG(duration_ms) FILTER (WHERE duration_ms IS NOT NULL) as avg_duration_ms,
    MAX(duration_ms) FILTER (WHERE duration_ms IS NOT NULL) as max_duration_ms,
    MIN(created_at) as first_operation_at,
    MAX(created_at) as last_operation_at
FROM audit_logs
WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY tenant_id, action, resource_type, DATE(created_at);

-- Create index on materialized view for fast queries
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_audit_stats_unique
    ON mv_audit_statistics (tenant_id, action, resource_type, audit_date);

CREATE INDEX IF NOT EXISTS idx_mv_audit_stats_date
    ON mv_audit_statistics (audit_date DESC);

COMMENT ON MATERIALIZED VIEW mv_audit_statistics IS 'Pre-aggregated audit statistics for analytics dashboards (refresh daily)';

-- Create function to refresh audit statistics
CREATE OR REPLACE FUNCTION refresh_audit_statistics()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_audit_statistics;
    RAISE NOTICE 'Audit statistics materialized view refreshed';
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION refresh_audit_statistics() IS 'Refreshes audit statistics materialized view (run daily via scheduler)';
