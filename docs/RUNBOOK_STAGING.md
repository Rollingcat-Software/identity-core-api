# Staging environment — identity-core-api (host-local)

Stood up 2026-05-29 (roadmap P1-2) to run E2E / adversarial tenant-isolation /
`@Filter` validation **off prod**, without littering the prod tenant list.

## What it is
- A second `identity-core-api` container (`identity-core-api-staging`) using the
  **already-built prod image** (`identity-core-api-identity-core-api:latest`).
- Bound to **`127.0.0.1:18080` only** (no Traefik route → not internet-exposed).
- Separate database **`identity_core_staging`** (same `shared-postgres`) + Redis
  logical **DB 1** → full data isolation from prod.
- **Mail disabled** (`MAIL_ENABLED=false`) and a **distinct `JWT_SECRET`**
  (staging tokens never validate on prod). Config: `docker-compose.staging.yml`
  + `.env.staging` (gitignored — secrets).

## Why the DB is CLONED, not migrated from scratch
> **DR fix landed 2026-05-30 (P1-5):** the from-zero failure described below is
> now resolved — `V29` resolves the flow/method by natural key, and `V40`/`V41`
> no longer carry a from-scratch PK-collision / invalid-COMMENT bug. A from-zero
> `flyway migrate` now reaches V71 cleanly (verified on a throwaway DB). Existing
> DBs (incl. this staging clone) need a one-time `flyway repair` for the three
> re-checksummed migrations — see `RUNBOOK_FLYWAY_V29_REPAIR.md`. Cloning is no
> longer strictly required for staging, but is still fine.

Historically, a from-zero Flyway run **failed**:
`V29__add_email_otp_to_default_login_flow.sql`
inserted an `auth_flow_steps` row referencing a default-login-flow that doesn't
exist in a from-scratch chain → `auth_flow_steps_auth_flow_id_fkey` violation
(it assumed a flow created out-of-band on prod). So staging is seeded by cloning prod's **schema + config/seed**
(PII-free): all DDL, `flyway_schema_history` (so Flyway sees V64, no re-migrate),
and the config tables (roles, permissions, auth_methods, tenants, auth_flows,
auth_flow_steps, tenant_email_domains, …) — but **no users/enrollments/audit**.

## Bring up (re-create the DB)
```bash
cd /opt/projects/fivucsas/identity-core-api
docker compose -f docker-compose.staging.yml --env-file .env.staging stop || true
docker exec shared-postgres psql -U postgres -c "DROP DATABASE IF EXISTS identity_core_staging WITH (FORCE);"
docker exec shared-postgres psql -U postgres -c "CREATE DATABASE identity_core_staging;"
docker exec shared-postgres psql -U postgres -d identity_core_staging -c "CREATE EXTENSION IF NOT EXISTS vector;"
# schema (DDL only)
docker exec shared-postgres pg_dump -U postgres --schema-only identity_core | docker exec -i shared-postgres psql -U postgres -d identity_core_staging
# config/seed (NO user PII) + flyway history
docker exec shared-postgres pg_dump -U postgres --data-only \
  -t flyway_schema_history -t roles -t permissions -t role_permissions \
  -t auth_methods -t tenants -t tenant_auth_methods -t auth_flows -t auth_flow_steps -t tenant_email_domains \
  identity_core | docker exec -i shared-postgres psql -U postgres -d identity_core_staging
docker compose -f docker-compose.staging.yml --env-file .env.staging up -d
# health: curl -s http://127.0.0.1:18080/actuator/health
```

## Seed a login fixture (e2e tenant has a password-only default flow)
```sql
-- bcrypt of SweepTest!2026 ; assign global SUPER_ADMIN role 10000000-…
INSERT INTO users (id,tenant_id,email,email_verified,first_name,last_name,is_active,is_locked,failed_login_attempts,user_type,status,password_hash,created_at,updated_at)
VALUES ('e2e00000-0000-0000-0000-0000000000a1','e2e00000-0000-0000-0000-000000000001','staging-admin@fivucsas.local',true,'Staging','Admin',true,false,0,'ROOT','ACTIVE','<bcrypt>',now(),now());
INSERT INTO user_roles (user_id,role_id,assigned_at) VALUES ('e2e00000-0000-0000-0000-0000000000a1','10000000-0000-0000-0000-000000000001',now());
```
Login: `POST http://127.0.0.1:18080/api/v1/auth/login {"email":"staging-admin@fivucsas.local","password":"SweepTest!2026"}`.

## To validate an api change off-prod
Rebuild the image, then run staging from it (`up -d`), exercise via `:18080`,
and only deploy to prod once staging is green. Tear down: `docker compose
-f docker-compose.staging.yml --env-file .env.staging down`.

## TODO (follow-ups)
- Staging WEB build (`VITE_API_BASE_URL=http://localhost:18080/api/v1`) + wire
  Playwright E2E (web-app/e2e) to run against staging on PRs (the CI E2E gate the
  roadmap's P1-1 needs).
- ~~Fix the V29 from-scratch failure so the chain is DR-safe.~~ **DONE 2026-05-30
  (P1-5)** — V29 (+ V40/V41 latent from-scratch bugs) fixed; chain reaches V71 from
  zero. See `RUNBOOK_FLYWAY_V29_REPAIR.md` (existing DBs need one `flyway repair`).
