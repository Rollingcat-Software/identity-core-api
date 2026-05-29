# Runbook — Marmara University demo/verify login flow

**Date:** 2026-05-29
**Why:** demo.fivucsas.com (Marmara University tenant) defaulted to a PASSWORD-only
login, so verify.fivucsas.com's MFA UI (OTP/TOTP/QR code entry boxes) could not be
exercised end-to-end. Changed the tenant's default `APP_LOGIN` flow to require a
second factor the tester picks at login.

This is **prod-data only** (applied directly to the `identity_core` DB on the Hetzner
host); it is intentionally NOT a Flyway migration so it stays scoped to this one
tenant and is trivially reversible.

## What was applied

Tenant: `Marmara University` = `11111111-1111-1111-1111-111111111111`

New default flow `Marmara Login (Password + Pick-One MFA)`
(`f0000077-0000-0000-0000-000000000001`, `operation_type=APP_LOGIN`):

| Step | type | method(s) |
|------|------|-----------|
| 1 | SEQUENTIAL | PASSWORD (required) |
| 2 | CHOICE (required) | pick one of **EMAIL_OTP / TOTP / QR_CODE** (primary = EMAIL_OTP) |

- `EMAIL_OTP` needs **no enrollment** → admins (`ahmet.abdullah@marun.edu.tr`,
  `ayse.demir@marun.edu.tr`) can always complete login; no lockout.
- `TOTP` / `QR_CODE` require prior enrollment (surface as `enrolled:false` until the
  user enrols them via My Profile).
- The previous default `Marmara Simple Login` (`f0000099-…`, PASSWORD-only) is kept
  **active but not default** for instant rollback.

Free-tier choices only — `SMS_OTP` (Twilio cost) and biometrics/NFC/hardware
(enrollment + hardware) were deliberately excluded from the picker.

## Apply (idempotent)

See the `INSERT … ON CONFLICT DO NOTHING` block run on 2026-05-29; re-runnable:

```sql
-- (flow + 2 steps + 3 auth_flow_step_methods rows, then promote to default)
-- full SQL preserved in the 2026-05-29 session notes / git history of this runbook.
```

## Rollback (restore PASSWORD-only default)

```sql
BEGIN;
UPDATE auth_flows SET is_default=false, updated_at=now()
 WHERE id='f0000077-0000-0000-0000-000000000001';
UPDATE auth_flows SET is_default=true, updated_at=now()
 WHERE id='f0000099-0000-0000-0000-000000000001';  -- Marmara Simple Login (PASSWORD only)
COMMIT;
```

To fully remove the test flow afterwards:
```sql
DELETE FROM auth_flows WHERE id='f0000077-0000-0000-0000-000000000001';
-- auth_flow_steps + auth_flow_step_methods cascade.
```

## Verify

```sql
SELECT name, is_default, is_active FROM auth_flows
 WHERE tenant_id='11111111-1111-1111-1111-111111111111'
   AND operation_type='APP_LOGIN' AND is_default=true;   -- exactly ONE row
```

> ⚠️ Exactly one `(tenant_id, operation_type)` may be `is_default=true AND is_active=true`
> — the login resolver uses `Optional`. Always dethrone the old default in the same
> transaction when promoting a new one (direct SQL does not auto-dethrone the way the
> `updateFlow` API does).
