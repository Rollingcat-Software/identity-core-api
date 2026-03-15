-- V16: Multi-Modal Authentication Flow System
-- Creates tables for configurable multi-step authentication flows
-- Supports 10 auth methods across web, mobile, and desktop platforms
-- NOTE: Made idempotent with IF NOT EXISTS / ON CONFLICT DO NOTHING

-- ============================================================================
-- TABLE: auth_methods (system-level method definitions)
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth_methods (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type            VARCHAR(30)    NOT NULL UNIQUE,
    name            VARCHAR(100)   NOT NULL,
    description     TEXT,
    category        VARCHAR(20)    NOT NULL,
    platforms       TEXT[]         NOT NULL,
    requires_enrollment BOOLEAN    NOT NULL DEFAULT false,
    is_active       BOOLEAN        NOT NULL DEFAULT true,
    config_schema   JSONB          DEFAULT '{}',
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

DO $$ BEGIN
    ALTER TABLE auth_methods ADD CONSTRAINT chk_auth_method_type
        CHECK (type IN ('PASSWORD','EMAIL_OTP','SMS_OTP','TOTP','QR_CODE','FACE','FINGERPRINT','VOICE','NFC_DOCUMENT','HARDWARE_KEY'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE auth_methods ADD CONSTRAINT chk_auth_method_category
        CHECK (category IN ('BASIC','STANDARD','PREMIUM','ENTERPRISE'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_auth_methods_type ON auth_methods(type);
CREATE INDEX IF NOT EXISTS idx_auth_methods_active ON auth_methods(is_active) WHERE is_active = true;

-- ============================================================================
-- TABLE: tenant_auth_methods (per-tenant method configuration)
-- ============================================================================
CREATE TABLE IF NOT EXISTS tenant_auth_methods (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID           NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    auth_method_id  UUID           NOT NULL REFERENCES auth_methods(id) ON DELETE CASCADE,
    is_enabled      BOOLEAN        NOT NULL DEFAULT true,
    config          JSONB          DEFAULT '{}',
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tenant_auth_method UNIQUE (tenant_id, auth_method_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_auth_methods_tenant ON tenant_auth_methods(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_auth_methods_enabled ON tenant_auth_methods(tenant_id, is_enabled) WHERE is_enabled = true;

-- ============================================================================
-- TABLE: auth_flows (named flows per tenant per operation type)
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth_flows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID           NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(100)   NOT NULL,
    description     TEXT,
    operation_type  VARCHAR(30)    NOT NULL,
    is_default      BOOLEAN        NOT NULL DEFAULT false,
    is_active       BOOLEAN        NOT NULL DEFAULT true,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_auth_flow_name UNIQUE (tenant_id, name)
);

DO $$ BEGIN
    ALTER TABLE auth_flows ADD CONSTRAINT chk_operation_type
        CHECK (operation_type IN ('APP_LOGIN','DOOR_ACCESS','BUILDING_ACCESS','API_ACCESS','TRANSACTION','ENROLLMENT','GUEST_ACCESS','EXAM_PROCTORING','CUSTOM'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_auth_flows_tenant ON auth_flows(tenant_id);
CREATE INDEX IF NOT EXISTS idx_auth_flows_tenant_operation ON auth_flows(tenant_id, operation_type);
CREATE INDEX IF NOT EXISTS idx_auth_flows_default ON auth_flows(tenant_id, operation_type, is_default) WHERE is_default = true;
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_flow_default ON auth_flows(tenant_id, operation_type) WHERE is_default = true AND is_active = true;

-- ============================================================================
-- TABLE: auth_flow_steps (ordered steps within a flow)
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth_flow_steps (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_flow_id        UUID           NOT NULL REFERENCES auth_flows(id) ON DELETE CASCADE,
    auth_method_id      UUID           NOT NULL REFERENCES auth_methods(id),
    step_order          INTEGER        NOT NULL,
    is_required         BOOLEAN        NOT NULL DEFAULT true,
    timeout_seconds     INTEGER        NOT NULL DEFAULT 120,
    max_attempts        INTEGER        NOT NULL DEFAULT 3,
    fallback_method_id  UUID           REFERENCES auth_methods(id),
    allows_delegation   BOOLEAN        NOT NULL DEFAULT true,
    config              JSONB          DEFAULT '{}',
    CONSTRAINT uq_flow_step_order UNIQUE (auth_flow_id, step_order),
    CONSTRAINT chk_step_order_positive CHECK (step_order > 0),
    CONSTRAINT chk_timeout_positive CHECK (timeout_seconds > 0 AND timeout_seconds <= 600),
    CONSTRAINT chk_max_attempts CHECK (max_attempts > 0 AND max_attempts <= 10),
    CONSTRAINT chk_no_self_fallback CHECK (auth_method_id != fallback_method_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_flow_steps_flow ON auth_flow_steps(auth_flow_id);
CREATE INDEX IF NOT EXISTS idx_auth_flow_steps_order ON auth_flow_steps(auth_flow_id, step_order);

-- ============================================================================
-- TABLE: auth_sessions (runtime auth session tracking)
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID           REFERENCES users(id),
    tenant_id           UUID           NOT NULL REFERENCES tenants(id),
    auth_flow_id        UUID           NOT NULL REFERENCES auth_flows(id),
    operation_type      VARCHAR(30)    NOT NULL,
    status              VARCHAR(20)    NOT NULL DEFAULT 'CREATED',
    current_step_order  INTEGER        NOT NULL DEFAULT 1,
    client_platform     VARCHAR(20),
    client_device_id    VARCHAR(255),
    ip_address          VARCHAR(45),
    user_agent          TEXT,
    started_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMP WITH TIME ZONE,
    expires_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    metadata            JSONB          DEFAULT '{}'
);

DO $$ BEGIN
    ALTER TABLE auth_sessions ADD CONSTRAINT chk_session_status
        CHECK (status IN ('CREATED','IN_PROGRESS','COMPLETED','FAILED','EXPIRED','CANCELLED'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_tenant ON auth_sessions(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at) WHERE status IN ('CREATED','IN_PROGRESS');
CREATE INDEX IF NOT EXISTS idx_auth_sessions_created ON auth_sessions(started_at DESC);

-- ============================================================================
-- TABLE: auth_session_steps (per-step status within a session)
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth_session_steps (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          UUID           NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    auth_flow_step_id   UUID           NOT NULL REFERENCES auth_flow_steps(id),
    method_type         VARCHAR(30)    NOT NULL,
    status              VARCHAR(20)    NOT NULL DEFAULT 'PENDING',
    attempt_count       INTEGER        NOT NULL DEFAULT 0,
    delegated           BOOLEAN        NOT NULL DEFAULT false,
    delegation_token    VARCHAR(255),
    delegation_device_id VARCHAR(255),
    delegation_expires  TIMESTAMP WITH TIME ZONE,
    started_at          TIMESTAMP WITH TIME ZONE,
    completed_at        TIMESTAMP WITH TIME ZONE,
    result              JSONB          DEFAULT '{}',
    CONSTRAINT uq_session_step UNIQUE (session_id, auth_flow_step_id),
    CONSTRAINT chk_step_status CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','FAILED','SKIPPED','DELEGATED'))
);

CREATE INDEX IF NOT EXISTS idx_auth_session_steps_session ON auth_session_steps(session_id);
CREATE INDEX IF NOT EXISTS idx_auth_session_steps_delegation ON auth_session_steps(delegation_token) WHERE delegation_token IS NOT NULL;

-- ============================================================================
-- TABLE: user_devices (registered user devices)
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID           NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id           UUID           NOT NULL REFERENCES tenants(id),
    device_name         VARCHAR(100),
    platform            VARCHAR(20)    NOT NULL,
    device_fingerprint  VARCHAR(255)   NOT NULL,
    capabilities        TEXT[]         NOT NULL DEFAULT '{}',
    push_token          TEXT,
    is_trusted          BOOLEAN        NOT NULL DEFAULT false,
    last_used_at        TIMESTAMP WITH TIME ZONE,
    registered_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_user_device UNIQUE (user_id, device_fingerprint),
    CONSTRAINT chk_device_platform CHECK (platform IN ('WEB','ANDROID','IOS','DESKTOP'))
);

CREATE INDEX IF NOT EXISTS idx_user_devices_user ON user_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_tenant ON user_devices(tenant_id);

-- ============================================================================
-- TABLE: user_enrollments (enrollment status per user per method)
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_enrollments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID           NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id           UUID           NOT NULL REFERENCES tenants(id),
    auth_method_type    VARCHAR(30)    NOT NULL,
    status              VARCHAR(20)    NOT NULL DEFAULT 'NOT_ENROLLED',
    enrollment_data     JSONB          DEFAULT '{}',
    enrolled_at         TIMESTAMP WITH TIME ZONE,
    expires_at          TIMESTAMP WITH TIME ZONE,
    revoked_at          TIMESTAMP WITH TIME ZONE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_user_enrollment UNIQUE (user_id, auth_method_type, tenant_id),
    CONSTRAINT chk_enrollment_status CHECK (status IN ('NOT_ENROLLED','PENDING','ENROLLED','FAILED','REVOKED','EXPIRED')),
    CONSTRAINT chk_enrollment_method CHECK (auth_method_type IN ('PASSWORD','EMAIL_OTP','SMS_OTP','TOTP','QR_CODE','FACE','FINGERPRINT','VOICE','NFC_DOCUMENT','HARDWARE_KEY'))
);

CREATE INDEX IF NOT EXISTS idx_user_enrollments_user ON user_enrollments(user_id);
CREATE INDEX IF NOT EXISTS idx_user_enrollments_tenant ON user_enrollments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_enrollments_method ON user_enrollments(auth_method_type, status);

-- ============================================================================
-- SEED DATA: auth_methods (10 records)
-- ============================================================================
INSERT INTO auth_methods (type, name, description, category, platforms, requires_enrollment, is_active) VALUES
('PASSWORD',     'Password',          'Traditional password authentication',       'BASIC',      '{WEB,ANDROID,IOS,DESKTOP}', true,  true),
('EMAIL_OTP',    'Email OTP',         'One-time password sent via email',          'BASIC',      '{WEB,ANDROID,IOS,DESKTOP}', false, true),
('SMS_OTP',      'SMS OTP',           'One-time password sent via SMS',            'STANDARD',   '{WEB,ANDROID,IOS,DESKTOP}', true,  true),
('TOTP',         'Authenticator App', 'Time-based OTP via authenticator app',      'STANDARD',   '{WEB,ANDROID,IOS,DESKTOP}', true,  true),
('QR_CODE',      'QR Code',           'Scan QR code for authentication',           'STANDARD',   '{WEB,ANDROID,IOS,DESKTOP}', true,  true),
('FACE',         'Face Recognition',  'Biometric face verification',               'PREMIUM',    '{WEB,ANDROID,IOS,DESKTOP}', true,  true),
('FINGERPRINT',  'Fingerprint',       'Biometric fingerprint verification',        'PREMIUM',    '{ANDROID,IOS,DESKTOP}',     true,  true),
('VOICE',        'Voice Recognition', 'Biometric voice verification',              'PREMIUM',    '{WEB,ANDROID,IOS,DESKTOP}', true,  false),
('NFC_DOCUMENT', 'NFC Document',      'ID document verification via NFC',          'ENTERPRISE', '{ANDROID,IOS}',             true,  true),
('HARDWARE_KEY', 'Hardware Key',      'FIDO2/WebAuthn hardware security key',      'ENTERPRISE', '{WEB,ANDROID,IOS,DESKTOP}', true,  true)
ON CONFLICT (type) DO NOTHING;

-- ============================================================================
-- SEED DATA: system tenant default auth method + flow
-- ============================================================================
INSERT INTO tenant_auth_methods (tenant_id, auth_method_id, is_enabled)
SELECT t.id, am.id, true
FROM tenants t, auth_methods am
WHERE t.name = 'system' AND am.type = 'PASSWORD'
ON CONFLICT ON CONSTRAINT uq_tenant_auth_method DO NOTHING;

INSERT INTO auth_flows (tenant_id, name, description, operation_type, is_default, is_active)
SELECT t.id, 'Default Login', 'Standard password authentication', 'APP_LOGIN', true, true
FROM tenants t WHERE t.name = 'system'
ON CONFLICT ON CONSTRAINT uq_auth_flow_name DO NOTHING;

INSERT INTO auth_flow_steps (auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts)
SELECT af.id, am.id, 1, true, 120, 5
FROM auth_flows af
JOIN tenants t ON af.tenant_id = t.id
JOIN auth_methods am ON am.type = 'PASSWORD'
WHERE t.name = 'system' AND af.name = 'Default Login'
ON CONFLICT ON CONSTRAINT uq_flow_step_order DO NOTHING;

-- Enroll existing admin user with PASSWORD
INSERT INTO user_enrollments (user_id, tenant_id, auth_method_type, status, enrolled_at)
SELECT u.id, u.tenant_id, 'PASSWORD', 'ENROLLED', u.created_at
FROM users u WHERE u.email = 'admin@fivucsas.local'
ON CONFLICT ON CONSTRAINT uq_user_enrollment DO NOTHING;

-- ============================================================================
-- SEED DATA: new RBAC permissions for auth flow management
-- ============================================================================
INSERT INTO permissions (name, description, resource, action) VALUES
('auth_flow:read',       'Read auth flows',         'auth_flow',    'read'),
('auth_flow:create',     'Create auth flows',       'auth_flow',    'create'),
('auth_flow:update',     'Update auth flows',       'auth_flow',    'update'),
('auth_flow:delete',     'Delete auth flows',       'auth_flow',    'delete'),
('auth_method:read',     'Read auth methods',       'auth_method',  'read'),
('auth_method:configure','Configure auth methods',  'auth_method',  'configure'),
('device:read',          'Read devices',            'device',       'read'),
('device:register',      'Register devices',        'device',       'register'),
('device:delete',        'Delete devices',           'device',       'delete'),
('enrollment:read',      'Read enrollments',        'enrollment',   'read'),
('enrollment:create',    'Create enrollments',      'enrollment',   'create'),
('enrollment:delete',    'Delete enrollments',      'enrollment',   'delete')
ON CONFLICT (name) DO NOTHING;
