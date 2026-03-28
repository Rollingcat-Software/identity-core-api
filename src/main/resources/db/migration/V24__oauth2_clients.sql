-- V24: Create OAuth 2.0 clients table for embeddable auth widget support

CREATE TABLE IF NOT EXISTS oauth2_clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       VARCHAR(128)  NOT NULL UNIQUE,
    client_secret   VARCHAR(255)  NOT NULL,
    client_name     VARCHAR(255)  NOT NULL,
    redirect_uris   TEXT          NOT NULL,
    allowed_scopes  VARCHAR(500)  NOT NULL DEFAULT 'openid profile email',
    tenant_id       UUID          NOT NULL REFERENCES tenants(id),
    active          BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth2_clients_client_id  ON oauth2_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_tenant_id  ON oauth2_clients(tenant_id);

-- Insert default client for the web-app dashboard
-- client_secret is bcrypt hash of 'fivucsas-web-app-secret-2026'
INSERT INTO oauth2_clients (client_id, client_secret, client_name, redirect_uris, allowed_scopes, tenant_id, active)
SELECT
    'fivucsas-web-dashboard',
    '$2a$12$LJ3m5Zq2q6P8W5X9c7xAneKbK3YvW2VxJd5S8V4E1mQ7JR9W8q9uy',
    'FIVUCSAS Web Dashboard',
    '["https://ica-fivucsas.rollingcatsoftware.com/callback","http://localhost:5173/callback","http://localhost:3000/callback"]',
    'openid profile email',
    t.id,
    TRUE
FROM tenants t
WHERE t.slug = 'system'
LIMIT 1;
