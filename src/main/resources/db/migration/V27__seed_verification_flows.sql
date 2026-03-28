-- V27: Seed standard verification flows
-- Creates pre-configured VERIFICATION flows for common industry use cases.
-- These flows reference auth_methods seeded in V26 (DOCUMENT_SCAN, FACE_MATCH, etc.)

-- ============================================================================
-- 1. Simple Document Verification (DOCUMENT_SCAN + FACE_MATCH)
-- ============================================================================
INSERT INTO auth_flows (id, tenant_id, name, description, operation_type, is_default, is_active, flow_type, industry_template)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000000',
    'Simple Document Verification',
    'Basic document scan and face match verification',
    'APP_LOGIN',
    false,
    true,
    'VERIFICATION',
    'SIMPLE_DOCUMENT'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', id, 1, true, 120, 3, false, '{}'
FROM auth_methods WHERE type = 'DOCUMENT_SCAN'
ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', id, 2, true, 120, 3, false, '{}'
FROM auth_methods WHERE type = 'FACE_MATCH'
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- 2. Healthcare Basic (DOCUMENT_SCAN + FACE_MATCH + LIVENESS_CHECK)
-- ============================================================================
INSERT INTO auth_flows (id, tenant_id, name, description, operation_type, is_default, is_active, flow_type, industry_template)
VALUES (
    'a0000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000000',
    'Healthcare Basic',
    'Patient identity verification for healthcare',
    'APP_LOGIN',
    false,
    true,
    'VERIFICATION',
    'HEALTHCARE_BASIC'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000002', id, 1, true, 120, 3, false, '{}'
FROM auth_methods WHERE type = 'DOCUMENT_SCAN'
ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000002', id, 2, true, 120, 3, false, '{}'
FROM auth_methods WHERE type = 'FACE_MATCH'
ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000002', id, 3, true, 120, 3, false, '{}'
FROM auth_methods WHERE type = 'LIVENESS_CHECK'
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- 3. Fintech KYC (full pipeline)
-- ============================================================================
INSERT INTO auth_flows (id, tenant_id, name, description, operation_type, is_default, is_active, flow_type, industry_template)
VALUES (
    'a0000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000000',
    'Fintech KYC',
    'Full KYC pipeline for financial services',
    'APP_LOGIN',
    false,
    true,
    'VERIFICATION',
    'FINTECH_KYC'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-000000000006', 'a0000000-0000-0000-0000-000000000003', id, 1, true, 120, 3, false, '{}'
FROM auth_methods WHERE type = 'DOCUMENT_SCAN'
ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-000000000007', 'a0000000-0000-0000-0000-000000000003', id, 2, true, 180, 3, false, '{}'
FROM auth_methods WHERE type = 'NFC_CHIP_READ'
ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-000000000008', 'a0000000-0000-0000-0000-000000000003', id, 3, true, 120, 3, false, '{}'
FROM auth_methods WHERE type = 'DATA_EXTRACT'
ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-000000000009', 'a0000000-0000-0000-0000-000000000003', id, 4, true, 120, 3, false, '{}'
FROM auth_methods WHERE type = 'FACE_MATCH'
ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts, allows_delegation, config)
SELECT 'b0000000-0000-0000-0000-00000000000a', 'a0000000-0000-0000-0000-000000000003', id, 5, true, 120, 3, false, '{}'
FROM auth_methods WHERE type = 'LIVENESS_CHECK'
ON CONFLICT (id) DO NOTHING;
