-- Test data for integration tests
-- Creates a default tenant for testing

-- Insert default test tenant with all required fields
INSERT INTO tenants (
    id,
    name,
    slug,
    description,
    contact_email,
    contact_phone,
    status,
    max_users,
    biometric_enabled,
    session_timeout_minutes,
    refresh_token_validity_days,
    mfa_required,
    created_at,
    updated_at
)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Test Tenant',
    'test-tenant',
    'Default tenant for integration tests',
    'test@fivucsas.com',
    '+1234567890',
    'ACTIVE',
    1000,
    true,
    30,
    7,
    false,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);
