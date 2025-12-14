-- V9: Create Rate Limiting Table
-- Persistent rate limiting storage for API request throttling across service restarts
-- Implements token bucket algorithm with distributed support

-- Rate limiting buckets table
CREATE TABLE IF NOT EXISTS rate_limit_buckets
(
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Rate limit key (e.g., 'ip:192.168.1.1', 'user:uuid', 'endpoint:/api/auth/login')
    limit_key       VARCHAR(500) NOT NULL UNIQUE,

    -- Rate limit type for categorization
    limit_type      VARCHAR(50)  NOT NULL, -- 'IP', 'USER', 'ENDPOINT', 'TENANT', 'GLOBAL'

    -- Token bucket algorithm state
    bucket_tokens   DECIMAL(10, 2) NOT NULL DEFAULT 0 CHECK (bucket_tokens >= 0),
    max_tokens      DECIMAL(10, 2) NOT NULL DEFAULT 100,
    refill_rate     DECIMAL(10, 2) NOT NULL DEFAULT 10, -- Tokens per second

    -- Timing
    last_refill_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP, -- Optional expiration for automatic cleanup

    -- Tracking
    request_count   BIGINT    DEFAULT 0, -- Total requests processed
    blocked_count   BIGINT    DEFAULT 0, -- Total requests blocked
    first_seen_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Metadata for additional context
    metadata        JSONB     DEFAULT '{}',

    -- Timestamps
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Indexes for performance
-- Primary lookup index by key
-- Rollback: DROP INDEX idx_rate_limit_key;
CREATE INDEX IF NOT EXISTS idx_rate_limit_key
    ON rate_limit_buckets (limit_key);

COMMENT ON INDEX idx_rate_limit_key IS 'Fast lookup of rate limit buckets by key';

-- Index by type for management queries
-- Rollback: DROP INDEX idx_rate_limit_type;
CREATE INDEX IF NOT EXISTS idx_rate_limit_type
    ON rate_limit_buckets (limit_type);

COMMENT ON INDEX idx_rate_limit_type IS 'Queries rate limits by category';

-- Partial index for expired buckets cleanup
-- Rollback: DROP INDEX idx_rate_limit_expired;
CREATE INDEX IF NOT EXISTS idx_rate_limit_expired
    ON rate_limit_buckets (expires_at)
    WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP;

COMMENT ON INDEX idx_rate_limit_expired IS 'Identifies expired rate limit buckets for cleanup';

-- Index for bucket refill operations
-- Rollback: DROP INDEX idx_rate_limit_refill;
CREATE INDEX IF NOT EXISTS idx_rate_limit_refill
    ON rate_limit_buckets (last_refill_at)
    WHERE bucket_tokens < max_tokens;

COMMENT ON INDEX idx_rate_limit_refill IS 'Optimizes token refill operations';

-- Composite index for hot buckets (frequently accessed)
-- Rollback: DROP INDEX idx_rate_limit_hot_buckets;
CREATE INDEX IF NOT EXISTS idx_rate_limit_hot_buckets
    ON rate_limit_buckets (limit_type, last_seen_at DESC)
    WHERE last_seen_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour';

COMMENT ON INDEX idx_rate_limit_hot_buckets IS 'Identifies actively used rate limit buckets';

-- GIN index for metadata queries
-- Rollback: DROP INDEX idx_rate_limit_metadata_gin;
CREATE INDEX IF NOT EXISTS idx_rate_limit_metadata_gin
    ON rate_limit_buckets USING GIN (metadata)
    WHERE metadata IS NOT NULL AND metadata != '{}'::jsonb;

COMMENT ON INDEX idx_rate_limit_metadata_gin IS 'Enables JSON queries on rate limit metadata';

-- Comments
COMMENT ON TABLE rate_limit_buckets IS 'Persistent storage for distributed rate limiting using token bucket algorithm';
COMMENT ON COLUMN rate_limit_buckets.limit_key IS 'Unique identifier for rate limit bucket (IP, user ID, endpoint, etc.)';
COMMENT ON COLUMN rate_limit_buckets.limit_type IS 'Category of rate limit for management and reporting';
COMMENT ON COLUMN rate_limit_buckets.bucket_tokens IS 'Current available tokens in the bucket';
COMMENT ON COLUMN rate_limit_buckets.max_tokens IS 'Maximum bucket capacity (burst limit)';
COMMENT ON COLUMN rate_limit_buckets.refill_rate IS 'Rate of token replenishment per second';
COMMENT ON COLUMN rate_limit_buckets.last_refill_at IS 'Last time tokens were refilled';
COMMENT ON COLUMN rate_limit_buckets.expires_at IS 'Automatic expiration timestamp for temporary limits';
COMMENT ON COLUMN rate_limit_buckets.request_count IS 'Total requests processed (for analytics)';
COMMENT ON COLUMN rate_limit_buckets.blocked_count IS 'Total requests blocked due to rate limit';

-- Trigger for automatic updated_at
CREATE TRIGGER update_rate_limit_buckets_updated_at
    BEFORE UPDATE ON rate_limit_buckets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TRIGGER update_rate_limit_buckets_updated_at ON rate_limit_buckets IS 'Automatically updates updated_at timestamp';

-- Function to consume tokens from bucket (atomic operation)
CREATE OR REPLACE FUNCTION consume_rate_limit_tokens(
    p_limit_key VARCHAR(500),
    p_tokens_requested DECIMAL DEFAULT 1.0,
    p_limit_type VARCHAR(50) DEFAULT 'GENERAL',
    p_max_tokens DECIMAL DEFAULT 100,
    p_refill_rate DECIMAL DEFAULT 10,
    p_expiry_seconds INTEGER DEFAULT NULL
)
RETURNS TABLE(
    allowed BOOLEAN,
    remaining_tokens DECIMAL,
    retry_after_seconds INTEGER
) AS $$
DECLARE
    v_bucket_tokens DECIMAL;
    v_last_refill_at TIMESTAMP;
    v_now TIMESTAMP := CURRENT_TIMESTAMP;
    v_time_elapsed_seconds DECIMAL;
    v_tokens_to_add DECIMAL;
    v_new_token_count DECIMAL;
    v_expires_at TIMESTAMP;
BEGIN
    -- Calculate expiration if specified
    IF p_expiry_seconds IS NOT NULL THEN
        v_expires_at := v_now + (p_expiry_seconds || ' seconds')::INTERVAL;
    END IF;

    -- Insert or get existing bucket (upsert pattern)
    INSERT INTO rate_limit_buckets (
        limit_key,
        limit_type,
        bucket_tokens,
        max_tokens,
        refill_rate,
        last_refill_at,
        expires_at,
        request_count,
        last_seen_at
    )
    VALUES (
        p_limit_key,
        p_limit_type,
        p_max_tokens - p_tokens_requested,
        p_max_tokens,
        p_refill_rate,
        v_now,
        v_expires_at,
        1,
        v_now
    )
    ON CONFLICT (limit_key) DO UPDATE SET
        last_seen_at = v_now,
        request_count = rate_limit_buckets.request_count + 1
    RETURNING bucket_tokens, last_refill_at
    INTO v_bucket_tokens, v_last_refill_at;

    -- If new insert, return allowed
    IF v_last_refill_at = v_now THEN
        RETURN QUERY SELECT TRUE, p_max_tokens - p_tokens_requested, 0;
        RETURN;
    END IF;

    -- Calculate time elapsed since last refill
    v_time_elapsed_seconds := EXTRACT(EPOCH FROM (v_now - v_last_refill_at));

    -- Calculate tokens to add based on refill rate
    v_tokens_to_add := p_refill_rate * v_time_elapsed_seconds;

    -- Calculate new token count (capped at max_tokens)
    v_new_token_count := LEAST(v_bucket_tokens + v_tokens_to_add, p_max_tokens);

    -- Check if we have enough tokens
    IF v_new_token_count >= p_tokens_requested THEN
        -- Consume tokens and update bucket
        UPDATE rate_limit_buckets
        SET bucket_tokens = v_new_token_count - p_tokens_requested,
            last_refill_at = v_now,
            last_seen_at = v_now,
            updated_at = v_now
        WHERE limit_key = p_limit_key;

        RETURN QUERY SELECT TRUE, v_new_token_count - p_tokens_requested, 0;
    ELSE
        -- Not enough tokens, calculate retry after
        DECLARE
            v_tokens_needed DECIMAL := p_tokens_requested - v_new_token_count;
            v_retry_after INTEGER := CEIL(v_tokens_needed / p_refill_rate);
        BEGIN
            -- Update blocked count
            UPDATE rate_limit_buckets
            SET bucket_tokens = v_new_token_count,
                last_refill_at = v_now,
                last_seen_at = v_now,
                blocked_count = blocked_count + 1,
                updated_at = v_now
            WHERE limit_key = p_limit_key;

            RETURN QUERY SELECT FALSE, v_new_token_count, v_retry_after;
        END;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION consume_rate_limit_tokens IS 'Atomically consumes tokens from rate limit bucket using token bucket algorithm';

-- Function to reset rate limit bucket
CREATE OR REPLACE FUNCTION reset_rate_limit_bucket(p_limit_key VARCHAR(500))
RETURNS BOOLEAN AS $$
BEGIN
    UPDATE rate_limit_buckets
    SET bucket_tokens = max_tokens,
        last_refill_at = CURRENT_TIMESTAMP,
        request_count = 0,
        blocked_count = 0,
        updated_at = CURRENT_TIMESTAMP
    WHERE limit_key = p_limit_key;

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION reset_rate_limit_bucket IS 'Resets a rate limit bucket to full capacity';

-- Function to cleanup expired and stale rate limit buckets
CREATE OR REPLACE FUNCTION cleanup_rate_limit_buckets()
RETURNS TABLE(deleted_expired INTEGER, deleted_stale INTEGER) AS $$
DECLARE
    v_deleted_expired INTEGER;
    v_deleted_stale INTEGER;
BEGIN
    -- Delete explicitly expired buckets
    DELETE FROM rate_limit_buckets
    WHERE expires_at IS NOT NULL
      AND expires_at < CURRENT_TIMESTAMP;

    GET DIAGNOSTICS v_deleted_expired = ROW_COUNT;

    -- Delete stale buckets (not seen in 24 hours)
    DELETE FROM rate_limit_buckets
    WHERE last_seen_at < CURRENT_TIMESTAMP - INTERVAL '24 hours'
      AND expires_at IS NULL; -- Don't delete if has explicit expiration

    GET DIAGNOSTICS v_deleted_stale = ROW_COUNT;

    RETURN QUERY SELECT v_deleted_expired, v_deleted_stale;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_rate_limit_buckets IS 'Removes expired and stale rate limit buckets (run periodically)';

-- Function to get rate limit status without consuming tokens
CREATE OR REPLACE FUNCTION get_rate_limit_status(p_limit_key VARCHAR(500))
RETURNS TABLE(
    limit_key VARCHAR,
    available_tokens DECIMAL,
    max_tokens DECIMAL,
    request_count BIGINT,
    blocked_count BIGINT,
    last_seen_at TIMESTAMP
) AS $$
DECLARE
    v_bucket_tokens DECIMAL;
    v_last_refill_at TIMESTAMP;
    v_max_tokens DECIMAL;
    v_refill_rate DECIMAL;
    v_now TIMESTAMP := CURRENT_TIMESTAMP;
    v_time_elapsed_seconds DECIMAL;
    v_tokens_to_add DECIMAL;
    v_available_tokens DECIMAL;
BEGIN
    -- Get bucket info
    SELECT
        rlb.bucket_tokens,
        rlb.last_refill_at,
        rlb.max_tokens,
        rlb.refill_rate
    INTO v_bucket_tokens, v_last_refill_at, v_max_tokens, v_refill_rate
    FROM rate_limit_buckets rlb
    WHERE rlb.limit_key = p_limit_key;

    -- If not found, return null
    IF NOT FOUND THEN
        RETURN;
    END IF;

    -- Calculate current available tokens
    v_time_elapsed_seconds := EXTRACT(EPOCH FROM (v_now - v_last_refill_at));
    v_tokens_to_add := v_refill_rate * v_time_elapsed_seconds;
    v_available_tokens := LEAST(v_bucket_tokens + v_tokens_to_add, v_max_tokens);

    -- Return status
    RETURN QUERY
    SELECT
        rlb.limit_key,
        v_available_tokens,
        rlb.max_tokens,
        rlb.request_count,
        rlb.blocked_count,
        rlb.last_seen_at
    FROM rate_limit_buckets rlb
    WHERE rlb.limit_key = p_limit_key;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_rate_limit_status IS 'Retrieves current rate limit status without consuming tokens';

-- Create view for rate limit monitoring
CREATE OR REPLACE VIEW v_rate_limit_monitoring AS
SELECT
    limit_key,
    limit_type,
    bucket_tokens,
    max_tokens,
    ROUND((bucket_tokens / max_tokens) * 100, 2) as capacity_percent,
    refill_rate,
    request_count,
    blocked_count,
    CASE
        WHEN request_count > 0 THEN ROUND((blocked_count::DECIMAL / request_count) * 100, 2)
        ELSE 0
    END as block_rate_percent,
    last_seen_at,
    CASE
        WHEN last_seen_at >= CURRENT_TIMESTAMP - INTERVAL '5 minutes' THEN 'ACTIVE'
        WHEN last_seen_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour' THEN 'IDLE'
        ELSE 'STALE'
    END as status,
    created_at
FROM rate_limit_buckets
ORDER BY last_seen_at DESC;

COMMENT ON VIEW v_rate_limit_monitoring IS 'Real-time monitoring view for rate limit buckets';

-- Insert default rate limit configurations
INSERT INTO rate_limit_buckets (limit_key, limit_type, bucket_tokens, max_tokens, refill_rate, metadata)
VALUES
    -- Global API rate limit
    ('global:api', 'GLOBAL', 10000, 10000, 100,
     '{"description": "Global API rate limit", "burst": 10000, "sustained": 100}'::jsonb),

    -- Authentication endpoint limits
    ('endpoint:/api/auth/login', 'ENDPOINT', 100, 100, 5,
     '{"description": "Login endpoint rate limit", "burst": 100, "sustained": 5}'::jsonb),

    ('endpoint:/api/auth/register', 'ENDPOINT', 50, 50, 2,
     '{"description": "Registration endpoint rate limit", "burst": 50, "sustained": 2}'::jsonb)
ON CONFLICT (limit_key) DO NOTHING;

COMMENT ON TABLE rate_limit_buckets IS 'Persistent rate limiting with token bucket algorithm for API throttling';
