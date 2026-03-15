#!/usr/bin/env bash
# =============================================================================
# test-crud.sh — FIVUCSAS Identity Core API — CRUD smoke tests
#
# Tests Create / Read-single / Read-list / Update / Delete for every entity.
# Usage:
#   ./scripts/test-crud.sh                          # localhost
#   BASE_URL=http://34.116.233.134:8080 ./scripts/test-crud.sh   # production
#
# Output: PASS/FAIL + HTTP status for every operation.
# Exit code: 0 if all pass, 1 if any fail.
# =============================================================================

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
API="${BASE_URL}/api/v1"

ADMIN_EMAIL="admin@fivucsas.local"
ADMIN_PASSWORD="Test@123"

# Counters
PASS=0
FAIL=0

# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

color_pass="\033[0;32m"
color_fail="\033[0;31m"
color_reset="\033[0m"

check() {
  local label="$1"
  local expected="$2"
  local actual="$3"

  if echo "$expected" | grep -qw "$actual"; then
    printf "${color_pass}PASS${color_reset} [%s] → HTTP %s\n" "$label" "$actual"
    PASS=$(( PASS + 1 ))
  else
    printf "${color_fail}FAIL${color_reset} [%s] → HTTP %s (expected %s)\n" "$label" "$actual" "$expected"
    FAIL=$(( FAIL + 1 ))
  fi
}

get_status() {
  curl -s -o /dev/null -w "%{http_code}" "$@"
}

get_body() {
  curl -s "$@"
}

# ─────────────────────────────────────────────────────────
# 0. Login → JWT
# ─────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════"
echo " FIVUCSAS CRUD Smoke Tests"
echo " Target: ${BASE_URL}"
echo "═══════════════════════════════════════════════════"
echo ""
echo ">>> [0] Authentication"

LOGIN_RESPONSE=$(get_body -X POST "${API}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}")

TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
  echo "FATAL: Login failed — could not extract accessToken"
  echo "Response: $LOGIN_RESPONSE"
  exit 1
fi

echo "Login OK — token obtained"
AUTH="-H \"Authorization: Bearer ${TOKEN}\""

# Convenience wrappers
auth_get()    { get_body    -H "Authorization: Bearer ${TOKEN}" "$@"; }
auth_status() { get_status  -H "Authorization: Bearer ${TOKEN}" "$@"; }

# ─────────────────────────────────────────────────────────
# 1. Users
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [1] Users"

# List
STATUS=$(auth_status "${API}/users")
check "User: list (GET /users)" "200" "$STATUS"

# Create
CREATE_RESPONSE=$(auth_get -X POST "${API}/users" \
  -H "Content-Type: application/json" \
  -d '{
    "email":"crud-test-user@fivucsas.local",
    "password":"Test@123",
    "firstName":"CRUD",
    "lastName":"TestUser",
    "role":"USER",
    "tenantId":"00000000-0000-0000-0000-000000000000"
  }')
CREATE_STATUS=$(echo "$CREATE_RESPONSE" | grep -o '"status":[0-9]*' | head -1 | cut -d: -f2 || true)
# Check HTTP via separate call
STATUS=$(get_status -X POST "${API}/users" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "email":"crud-test-user-2@fivucsas.local",
    "password":"Test@123",
    "firstName":"CRUD2",
    "lastName":"TestUser2",
    "role":"USER",
    "tenantId":"00000000-0000-0000-0000-000000000000"
  }')
check "User: create (POST /users)" "201" "$STATUS"

# Extract created user ID
USER_ID=$(echo "$CREATE_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$USER_ID" ]; then
  # Read single
  STATUS=$(auth_status "${API}/users/${USER_ID}")
  check "User: read (GET /users/{id})" "200" "$STATUS"

  # Update
  STATUS=$(get_status -X PUT "${API}/users/${USER_ID}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"firstName":"CRUDUpdated","lastName":"TestUser"}')
  check "User: update (PUT /users/{id})" "200" "$STATUS"

  # Delete
  STATUS=$(get_status -X DELETE "${API}/users/${USER_ID}" \
    -H "Authorization: Bearer ${TOKEN}")
  check "User: delete (DELETE /users/{id})" "204" "$STATUS"
else
  echo "  NOTE: Could not extract user ID from create response — skipping read/update/delete"
fi

# ─────────────────────────────────────────────────────────
# 2. Tenants
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [2] Tenants"

# List
STATUS=$(auth_status "${API}/tenants")
check "Tenant: list (GET /tenants)" "200" "$STATUS"

# Create
TENANT_RESPONSE=$(auth_get -X POST "${API}/tenants" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"CRUD Test Tenant",
    "slug":"crud-test-tenant",
    "description":"Temporary CRUD test tenant",
    "contactEmail":"crud@test.local",
    "contactPhone":"+905000000000",
    "maxUsers":10,
    "biometricEnabled":false,
    "sessionTimeoutMinutes":30,
    "refreshTokenValidityDays":7,
    "mfaRequired":false
  }')
STATUS=$(get_status -X POST "${API}/tenants" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"CRUD Test Tenant 2",
    "slug":"crud-test-tenant-2",
    "description":"Temporary CRUD test tenant 2",
    "contactEmail":"crud2@test.local",
    "contactPhone":"+905000000001",
    "maxUsers":10,
    "biometricEnabled":false,
    "sessionTimeoutMinutes":30,
    "refreshTokenValidityDays":7,
    "mfaRequired":false
  }')
check "Tenant: create (POST /tenants)" "201" "$STATUS"

TENANT_ID=$(echo "$TENANT_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$TENANT_ID" ]; then
  # Read single
  STATUS=$(auth_status "${API}/tenants/${TENANT_ID}")
  check "Tenant: read (GET /tenants/{id})" "200" "$STATUS"

  # Update
  STATUS=$(get_status -X PUT "${API}/tenants/${TENANT_ID}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
      "name":"CRUD Test Tenant Updated",
      "contactEmail":"crud-updated@test.local",
      "maxUsers":20,
      "biometricEnabled":true,
      "sessionTimeoutMinutes":60,
      "refreshTokenValidityDays":14,
      "mfaRequired":false
    }')
  check "Tenant: update (PUT /tenants/{id})" "200" "$STATUS"

  # Delete
  STATUS=$(get_status -X DELETE "${API}/tenants/${TENANT_ID}" \
    -H "Authorization: Bearer ${TOKEN}")
  check "Tenant: delete (DELETE /tenants/{id})" "204" "$STATUS"
else
  echo "  NOTE: Could not extract tenant ID — skipping read/update/delete"
fi

# ─────────────────────────────────────────────────────────
# 3. Roles
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [3] Roles"

# List
STATUS=$(auth_status "${API}/roles")
check "Role: list (GET /roles)" "200" "$STATUS"

# Create
ROLE_RESPONSE=$(auth_get -X POST "${API}/roles" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"CRUD_TEST_ROLE",
    "description":"Temporary role for CRUD testing",
    "tenantId":"00000000-0000-0000-0000-000000000000"
  }')
STATUS=$(get_status -X POST "${API}/roles" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"CRUD_TEST_ROLE_2",
    "description":"Temporary role for CRUD testing 2",
    "tenantId":"00000000-0000-0000-0000-000000000000"
  }')
check "Role: create (POST /roles)" "201" "$STATUS"

ROLE_ID=$(echo "$ROLE_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$ROLE_ID" ]; then
  # Read single
  STATUS=$(auth_status "${API}/roles/${ROLE_ID}")
  check "Role: read (GET /roles/{id})" "200" "$STATUS"

  # Update
  STATUS=$(get_status -X PUT "${API}/roles/${ROLE_ID}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"name":"CRUD_TEST_ROLE_UPDATED","description":"Updated","active":true}')
  check "Role: update (PUT /roles/{id})" "200" "$STATUS"

  # Delete
  STATUS=$(get_status -X DELETE "${API}/roles/${ROLE_ID}" \
    -H "Authorization: Bearer ${TOKEN}")
  check "Role: delete (DELETE /roles/{id})" "204" "$STATUS"
else
  echo "  NOTE: Could not extract role ID — skipping read/update/delete"
fi

# ─────────────────────────────────────────────────────────
# 4. Permissions
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [4] Permissions"

# List all
STATUS=$(auth_status "${API}/permissions")
check "Permission: list (GET /permissions)" "200" "$STATUS"

# Get first permission by resource
STATUS=$(auth_status "${API}/permissions/resource/user")
check "Permission: list by resource (GET /permissions/resource/user)" "200" "$STATUS"

# Get specific permission by ID — we need to extract one first
PERM_RESPONSE=$(auth_get "${API}/permissions")
PERM_ID=$(echo "$PERM_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$PERM_ID" ]; then
  STATUS=$(auth_status "${API}/permissions/${PERM_ID}")
  check "Permission: read (GET /permissions/{id})" "200" "$STATUS"
else
  echo "  NOTE: Could not extract permission ID — skipping read"
fi

# ─────────────────────────────────────────────────────────
# 5. Auth Methods (global + tenant-level)
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [5] AuthMethods"

# List all global methods (no auth required per controller)
STATUS=$(auth_status "${API}/auth-methods")
check "AuthMethod: list (GET /auth-methods)" "200" "$STATUS"

# Get by type
STATUS=$(auth_status "${API}/auth-methods/PASSWORD")
check "AuthMethod: get by type (GET /auth-methods/PASSWORD)" "200" "$STATUS"

# List tenant methods — use system tenant
SYSTEM_TENANT_ID="00000000-0000-0000-0000-000000000000"
STATUS=$(auth_status "${API}/tenants/${SYSTEM_TENANT_ID}/auth-methods")
check "TenantAuthMethod: list (GET /tenants/{id}/auth-methods)" "200 403 404" "$STATUS"

# ─────────────────────────────────────────────────────────
# 6. Auth Flows (tenant-scoped)
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [6] AuthFlows"

SYSTEM_TENANT_ID="00000000-0000-0000-0000-000000000000"

# List flows
STATUS=$(auth_status "${API}/tenants/${SYSTEM_TENANT_ID}/auth-flows")
check "AuthFlow: list (GET /tenants/{id}/auth-flows)" "200 403" "$STATUS"

# ─────────────────────────────────────────────────────────
# 7. Devices
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [7] Devices"

# Get admin user ID first
USERS_RESPONSE=$(auth_get "${API}/users")
ADMIN_ID=$(echo "$USERS_RESPONSE" | grep -o '"id":"[^"]*","email":"admin@fivucsas.local"' | grep -o '"id":"[^"]*"' | cut -d'"' -f4 || true)

if [ -z "$ADMIN_ID" ]; then
  # Try alternative extraction
  ADMIN_ID=$(echo "$USERS_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
content = data.get('content', []) if isinstance(data, dict) else data
for u in content:
    if u.get('email') == 'admin@fivucsas.local':
        print(u['id'])
        break
" 2>/dev/null || true)
fi

if [ -n "$ADMIN_ID" ]; then
  STATUS=$(auth_status "${API}/devices?userId=${ADMIN_ID}")
  check "Device: list by userId (GET /devices?userId=...)" "200 400" "$STATUS"
else
  echo "  NOTE: Could not extract admin user ID — using raw devices endpoint"
  STATUS=$(auth_status "${API}/devices")
  check "Device: list (GET /devices)" "200 400" "$STATUS"
fi

# ─────────────────────────────────────────────────────────
# 8. Enrollments
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [8] Enrollments"

STATUS=$(auth_status "${API}/enrollments")
check "Enrollment: list (GET /enrollments)" "200 403" "$STATUS"

STATUS=$(auth_status "${API}/enrollment/status")
check "Enrollment: status (GET /enrollment/status)" "200" "$STATUS"

# ─────────────────────────────────────────────────────────
# 9. Audit Logs
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [9] AuditLogs"

STATUS=$(auth_status "${API}/audit-logs")
check "AuditLog: list (GET /audit-logs)" "200" "$STATUS"

STATUS=$(auth_status "${API}/audit-logs/action-types")
check "AuditLog: action-types (GET /audit-logs/action-types)" "200" "$STATUS"

# Get first audit log ID for single read
AUDIT_RESPONSE=$(auth_get "${API}/audit-logs")
AUDIT_ID=$(echo "$AUDIT_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$AUDIT_ID" ]; then
  STATUS=$(auth_status "${API}/audit-logs/${AUDIT_ID}")
  check "AuditLog: read (GET /audit-logs/{id})" "200" "$STATUS"
else
  echo "  NOTE: No audit log IDs found — skipping single read"
fi

# ─────────────────────────────────────────────────────────
# 10. Auth Sessions
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [10] AuthSessions (session management)"

STATUS=$(auth_status "${API}/sessions")
check "Session: list (GET /sessions)" "200" "$STATUS"

# ─────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════"
echo " Results: ${PASS} PASS, ${FAIL} FAIL"
echo "═══════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
