-- V22: NFC Card Enrollment table
-- Stores NFC card serial -> user mappings for card-based authentication

CREATE TABLE IF NOT EXISTS nfc_cards (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    card_serial     VARCHAR(100) NOT NULL,
    card_type       VARCHAR(50) NOT NULL DEFAULT 'UNKNOWN',
    label           VARCHAR(100),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    enrolled_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_nfc_card_serial_tenant UNIQUE (card_serial, tenant_id)
);

CREATE INDEX idx_nfc_cards_user_id ON nfc_cards(user_id);
CREATE INDEX idx_nfc_cards_card_serial ON nfc_cards(card_serial);
CREATE INDEX idx_nfc_cards_tenant_id ON nfc_cards(tenant_id);
