# Migration V7, V8, V9 - Testing Checklist

## Pre-Migration Verification

- [ ] Backup production database
- [ ] Review migration files for syntax errors
- [ ] Test migrations on development database
- [ ] Verify application.properties/application.yml Flyway configuration

## Migration Execution

### Step 1: Run Migrations

This project uses **Maven** (not Gradle). There is no `flyway-maven-plugin`
in `pom.xml` — Flyway runs automatically on application startup via Spring Boot
auto-configuration.

```bash
# Start the application — Flyway applies pending migrations automatically
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

### Step 2: Verify Migration Status

```sql
-- Check Flyway schema history
SELECT * FROM flyway_schema_history ORDER BY installed_rank DESC;

-- Verify V7 indexes were created
SELECT indexname, tablename FROM pg_indexes
WHERE indexname LIKE 'idx_%'
  AND schemaname = 'public'
ORDER BY tablename, indexname;

-- Verify V8 columns were added
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'audit_logs'
  AND column_name IN ('request_id', 'duration_ms', 'user_agent_v2', 'enhanced_metadata');

-- Verify V9 table was created
SELECT table_name FROM information_schema.tables
WHERE table_name = 'rate_limit_buckets';
```

## Functional Testing

### V7: Performance Indexes

#### Test 1: Email Lookup Performance
```sql
-- Explain plan should show Index Scan on idx_users_email_unique
EXPLAIN ANALYZE
SELECT * FROM users WHERE email = 'admin@fivucsas.local' AND deleted_at IS NULL;
```

- [ ] Query uses index scan (not sequential scan)
- [ ] Query time < 10ms

#### Test 2: Tenant User Status Query
```sql
-- Explain plan should show Index Scan on idx_users_tenant_status
EXPLAIN ANALYZE
SELECT * FROM users
WHERE tenant_id = '00000000-0000-0000-0000-000000000000'
  AND is_active = true
  AND deleted_at IS NULL;
```

- [ ] Query uses composite index
- [ ] Query time < 20ms

#### Test 3: Audit Log Tenant Query
```sql
-- Explain plan should show Index Scan on idx_audit_tenant_created
EXPLAIN ANALYZE
SELECT * FROM audit_logs
WHERE tenant_id = '00000000-0000-0000-0000-000000000000'
ORDER BY created_at DESC
LIMIT 100;
```

- [ ] Query uses composite index
- [ ] Query time < 50ms

### V8: Audit Log Enhancements

#### Test 1: Insert Audit Log with New Fields
```sql
INSERT INTO audit_logs (
    tenant_id, user_id, action, resource_type, success,
    request_id, duration_ms, user_agent_v2, enhanced_metadata
) VALUES (
    '00000000-0000-0000-0000-000000000000',
    (SELECT id FROM users WHERE email = 'admin@fivucsas.local'),
    'TEST_ACTION',
    'TEST_RESOURCE',
    true,
    uuid_generate_v4(),
    150,
    'Mozilla/5.0 (Test Browser)',
    '{"test": "metadata", "environment": "testing"}'::jsonb
);
```

- [ ] Insert succeeds
- [ ] All new fields are populated
- [ ] Trigger `trg_populate_audit_request_id` executes

#### Test 2: Distributed Tracing Query
```sql
-- Generate test request ID
DO $$
DECLARE
    test_request_id UUID := uuid_generate_v4();
BEGIN
    -- Insert multiple audit logs with same request_id
    INSERT INTO audit_logs (tenant_id, action, resource_type, success, request_id, duration_ms)
    VALUES
        ('00000000-0000-0000-0000-000000000000', 'API_CALL_1', 'TEST', true, test_request_id, 50),
        ('00000000-0000-0000-0000-000000000000', 'API_CALL_2', 'TEST', true, test_request_id, 100),
        ('00000000-0000-0000-0000-000000000000', 'API_CALL_3', 'TEST', true, test_request_id, 75);

    -- Query by request_id
    RAISE NOTICE 'Test request ID: %', test_request_id;
END $$;

-- Verify distributed tracing
SELECT action, resource_type, duration_ms, created_at
FROM audit_logs
WHERE request_id IN (
    SELECT DISTINCT request_id FROM audit_logs WHERE action LIKE 'API_CALL_%'
)
ORDER BY created_at;
```

- [ ] All related audit logs are retrieved
- [ ] Index `idx_audit_request_id` is used
- [ ] Query time < 10ms

#### Test 3: Slow Operations Detection
```sql
-- Insert slow operation
INSERT INTO audit_logs (
    tenant_id, action, resource_type, endpoint, success, duration_ms
) VALUES (
    '00000000-0000-0000-0000-000000000000',
    'SLOW_OPERATION',
    'TEST',
    '/api/slow/endpoint',
    true,
    5000
);

-- Query slow operations
SELECT * FROM v_slow_operations LIMIT 10;
```

- [ ] View returns slow operations
- [ ] Operations with duration > 1000ms are included
- [ ] Query time < 20ms

#### Test 4: Audit Statistics Materialized View
```sql
-- Refresh materialized view
SELECT refresh_audit_statistics();

-- Query statistics
SELECT * FROM mv_audit_statistics
WHERE audit_date = CURRENT_DATE
ORDER BY total_operations DESC
LIMIT 10;
```

- [ ] Materialized view refreshes successfully
- [ ] Statistics are aggregated correctly
- [ ] Query time < 5ms

#### Test 5: Retention Policy
```sql
-- Test retention policy (dry run)
SELECT apply_audit_retention_policy();

-- Check archived logs
SELECT COUNT(*) FROM audit_logs
WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '90 days'
  AND (old_values IS NULL AND new_values IS NULL);
```

- [ ] Function executes without errors
- [ ] Old logs are archived (metadata removed)
- [ ] Logs older than 1 year are deleted

### V9: Rate Limiting

#### Test 1: Token Consumption
```sql
-- Create test bucket
INSERT INTO rate_limit_buckets (
    limit_key, limit_type, bucket_tokens, max_tokens, refill_rate
) VALUES (
    'test:bucket:1', 'TEST', 10, 10, 1
);

-- Consume tokens (should succeed)
SELECT * FROM consume_rate_limit_tokens('test:bucket:1', 5);

-- Verify result
-- Expected: allowed=true, remaining_tokens=5, retry_after_seconds=0

-- Consume more tokens (should succeed)
SELECT * FROM consume_rate_limit_tokens('test:bucket:1', 5);

-- Try to consume when empty (should fail)
SELECT * FROM consume_rate_limit_tokens('test:bucket:1', 1);

-- Expected: allowed=false, remaining_tokens=0, retry_after_seconds>0
```

- [ ] First consumption succeeds (5 tokens)
- [ ] Second consumption succeeds (5 tokens)
- [ ] Third consumption fails (no tokens)
- [ ] Retry-after is calculated correctly

#### Test 2: Token Refill
```sql
-- Wait for refill (1 token per second)
SELECT pg_sleep(3);

-- Try consuming again (should have ~3 tokens)
SELECT * FROM consume_rate_limit_tokens('test:bucket:1', 2);

-- Expected: allowed=true, remaining_tokens~=1
```

- [ ] Tokens are refilled over time
- [ ] Consumption succeeds after refill

#### Test 3: Rate Limit Status
```sql
-- Check status without consuming
SELECT * FROM get_rate_limit_status('test:bucket:1');
```

- [ ] Status shows current available tokens
- [ ] Status shows request and blocked counts
- [ ] No tokens are consumed

#### Test 4: Bucket Cleanup
```sql
-- Create expired bucket
INSERT INTO rate_limit_buckets (
    limit_key, limit_type, bucket_tokens, max_tokens, refill_rate, expires_at
) VALUES (
    'test:expired:1', 'TEST', 10, 10, 1, CURRENT_TIMESTAMP - INTERVAL '1 hour'
);

-- Run cleanup
SELECT * FROM cleanup_rate_limit_buckets();

-- Verify expired bucket is deleted
SELECT COUNT(*) FROM rate_limit_buckets WHERE limit_key = 'test:expired:1';

-- Expected: count=0
```

- [ ] Cleanup function executes
- [ ] Expired buckets are deleted
- [ ] Stale buckets are deleted

#### Test 5: Rate Limit Monitoring
```sql
-- View monitoring dashboard
SELECT * FROM v_rate_limit_monitoring ORDER BY last_seen_at DESC LIMIT 10;
```

- [ ] View shows all active buckets
- [ ] Capacity percentage is calculated
- [ ] Block rate percentage is calculated
- [ ] Status indicator is correct (ACTIVE/IDLE/STALE)

## Java Entity Testing

### Test 1: AuditLog Entity
```java
@Test
void testAuditLogEntity() {
    AuditLog auditLog = AuditLog.builder()
        .tenantId(UUID.randomUUID())
        .userId(UUID.randomUUID())
        .action("LOGIN")
        .resourceType("USER")
        .success(true)
        .requestId(UUID.randomUUID())
        .durationMs(150)
        .build();

    // Test security event detection
    assertTrue(auditLog.isSecurityEvent());
    assertFalse(auditLog.isFailed());
    assertFalse(auditLog.isSlowOperation());

    // Test with slow operation
    auditLog.setDurationMs(1500);
    assertTrue(auditLog.isSlowOperation());
}
```

- [ ] Entity builds correctly
- [ ] Helper methods work as expected
- [ ] JSONB fields are mapped correctly

### Test 2: RateLimitBucket Entity
```java
@Test
void testRateLimitBucketEntity() {
    RateLimitBucket bucket = RateLimitBucket.builder()
        .limitKey("test:key:1")
        .limitType("TEST")
        .bucketTokens(new BigDecimal("50"))
        .maxTokens(new BigDecimal("100"))
        .refillRate(new BigDecimal("10"))
        .requestCount(100L)
        .blockedCount(10L)
        .build();

    // Test capacity calculation
    assertEquals(50.0, bucket.getCapacityPercent());

    // Test block rate calculation
    assertEquals(10.0, bucket.getBlockRatePercent());

    // Test status checks
    assertFalse(bucket.isEmpty());
    assertFalse(bucket.isFull());
}
```

- [ ] Entity builds correctly
- [ ] Calculations are accurate
- [ ] Status checks work as expected

## Repository Testing

### Test 1: AuditLogRepository
```java
@Test
void testAuditLogRepository() {
    UUID tenantId = UUID.randomUUID();
    UUID requestId = UUID.randomUUID();

    // Create test audit logs
    AuditLog log1 = auditLogRepository.save(createTestLog(tenantId, requestId, 100));
    AuditLog log2 = auditLogRepository.save(createTestLog(tenantId, requestId, 200));

    // Test distributed tracing query
    List<AuditLog> logs = auditLogRepository.findByRequestIdOrderByCreatedAtAsc(requestId);
    assertEquals(2, logs.size());

    // Test slow operations query
    Page<AuditLog> slowOps = auditLogRepository.findSlowOperations(1000, PageRequest.of(0, 10));
    // Verify results
}
```

- [ ] Basic CRUD operations work
- [ ] Custom queries return correct results
- [ ] Pagination works correctly

### Test 2: RateLimitBucketRepository
```java
@Test
void testRateLimitBucketRepository() {
    String limitKey = "test:key:" + UUID.randomUUID();

    // Create test bucket
    RateLimitBucket bucket = rateLimitBucketRepository.save(
        RateLimitBucket.builder()
            .limitKey(limitKey)
            .limitType("TEST")
            .bucketTokens(new BigDecimal("100"))
            .maxTokens(new BigDecimal("100"))
            .refillRate(new BigDecimal("10"))
            .build()
    );

    // Test find by key
    Optional<RateLimitBucket> found = rateLimitBucketRepository.findByLimitKey(limitKey);
    assertTrue(found.isPresent());

    // Test reset
    rateLimitBucketRepository.resetBucket(limitKey);
    // Verify bucket is reset
}
```

- [ ] Basic CRUD operations work
- [ ] Custom queries return correct results
- [ ] Update operations work correctly

## Performance Benchmarks

### Baseline Measurements

Record baseline performance before migration:

```sql
-- Email lookup
\timing on
SELECT * FROM users WHERE email = 'admin@fivucsas.local';
\timing off

-- Tenant audit query
\timing on
SELECT * FROM audit_logs WHERE tenant_id = '...' ORDER BY created_at DESC LIMIT 100;
\timing off

-- Session validation
\timing on
SELECT * FROM active_sessions WHERE user_id = '...' AND is_active = true;
\timing off
```

### After Migration Measurements

Re-run the same queries and compare:

- [ ] Email lookup improved by >50%
- [ ] Audit query improved by >70%
- [ ] Session validation improved by >60%

## Rollback Testing

### Test Rollback Procedures

```sql
-- Test V9 rollback
BEGIN;
-- Execute rollback commands from MIGRATION_V7_V8_V9_SUMMARY.md
-- Verify table is dropped
SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'rate_limit_buckets';
ROLLBACK;

-- Repeat for V8 and V7 if needed
```

- [ ] Rollback commands are documented
- [ ] Rollback succeeds without errors
- [ ] Database returns to previous state

## Production Deployment Checklist

- [ ] All tests passed in development environment
- [ ] All tests passed in staging environment
- [ ] Performance benchmarks meet expectations
- [ ] Database backup completed
- [ ] Rollback procedure tested and documented
- [ ] Monitoring alerts configured
- [ ] Team notified of deployment window
- [ ] Post-deployment verification plan ready

## Post-Deployment Verification

- [ ] Check Flyway schema history
- [ ] Verify all indexes are created
- [ ] Run sample queries to test performance
- [ ] Monitor application logs for errors
- [ ] Check database CPU and memory usage
- [ ] Verify audit logs are being created correctly
- [ ] Test rate limiting functionality
- [ ] Monitor for any performance degradation

## Known Issues / Notes

- Record any issues encountered during testing
- Document any configuration changes needed
- Note any compatibility concerns

---

**Last Updated**: 2026-05-28
**Tested By**: _____________
**Environment**: _____________
**Status**: [ ] PASS / [ ] FAIL / [ ] PARTIAL
