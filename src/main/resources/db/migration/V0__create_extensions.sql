-- V0: Create Required PostgreSQL Extensions
-- These extensions must be created before any other migrations

-- UUID generation support
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- pgvector for biometric embeddings (if using pgvector)
CREATE EXTENSION IF NOT EXISTS "vector";
