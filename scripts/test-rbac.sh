#!/usr/bin/env bash
# =============================================================================
# test-rbac.sh — FIVUCSAS Identity Core API — RBAC verification tests
#
# Tests:
#   1. SUPER_ADMIN can access /api/v1/tenants → expect 200
#   2. TENANT_MEMBER cannot access /api/v1/tenants → expect 403
#   3. Unauthenticated request to /api/v1/users → expect 401
#   4. Missing JWT → expect 401
#   5. SUPER_ADMIN can access /api/v1/audit-logs → expect 200
#   6. SUPER_ADMIN can access /api/v1/roles → expect 200
#   7. TENANT_MEMBER cannot access /api/v1/roles (role:read) → expect 403
#   8. Expired/invalid token → expect 401
#
# Usage:
#   ./scripts/test-rbac.sh
#   BASE_URL=http://34.116.233.134:8080 ./scripts/test-rbac.sh
# =============================================================================

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
API="${BASE_URL}/api/v1"

# Credentials
ADMIN_EMAIL="admin@fivucsas.local"
ADMIN_PASSWORD="Test@123"

# TENANT_MEMBER from seed data (Marmara University user with USER role, no tenant:read perm)
MEMBER_EMAIL="mehmet.yilmaz@marmara.edu.tr"
MEMBER_PASSWORD="Test@123"

PASS=0
FAIL=0

color_pass="\033[0;32m"
color_fail="\033[0;31m"
color_reset="\033[0m"

check() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  local note="${4:-}"

  if echo "$expected" | grep -qw "$actual"; then
    printf "${color_pass}PASS${color_reset} [%s] → HTTP %s%s\n" "$label" "$actual" "${note:+ ($note)}"
    PASS=$(( PASS + 1 ))
  else
    printf "${color_fail}FAIL${color_reset} [%s] → HTTP %s (expected %s)%s\n" "$label" "$actual" "$expected" "${note:+ ($note)}"
    FAIL=$(( FAIL + 1 ))
  fi
}

get_status() {
  curl -s -o /dev/null -w "%{http_code}" "$@"
}

login() {
  local email="$1"
  local password="$2"
  curl -s -X POST "${API}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${email}\",\"password\":\"${password}\"}" \
    | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4
}

echo ""
echo "═══════════════════════════════════════════════════"
echo " FIVUCSAS RBAC Verification Tests"
echo " Target: ${BASE_URL}"
echo "═══════════════════════════════════════════════════"
echo ""

# ─────────────────────────────────────────────────────────
# Test 1 & 2: Unauthenticated + missing JWT → 401
# ─────────────────────────────────────────────────────────

echo ">>> [Auth] Unauthenticated access checks"

STATUS=$(get_status "${API}/users")
check "Unauth: GET /users (no token)" "401" "$STATUS"

STATUS=$(get_status "${API}/tenants")
check "Unauth: GET /tenants (no token)" "401" "$STATUS"

# Test with explicitly wrong/empty Authorization header
STATUS=$(get_status "${API}/users" -H "Authorization: ")
check "Unauth: GET /users (empty auth header)" "401" "$STATUS"

# Test with invalid/garbage token
STATUS=$(get_status "${API}/users" -H "Authorization: Bearer this.is.not.a.valid.jwt")
check "Unauth: GET /users (invalid token)" "401" "$STATUS"

# ─────────────────────────────────────────────────────────
# Test 3: SUPER_ADMIN has full access
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [SUPER_ADMIN] Admin access checks"

ADMIN_TOKEN=$(login "$ADMIN_EMAIL" "$ADMIN_PASSWORD")

if [ -z "$ADMIN_TOKEN" ]; then
  echo "FATAL: Admin login failed — cannot continue RBAC tests"
  exit 1
fi

echo "  Admin login OK"

STATUS=$(get_status "${API}/tenants" -H "Authorization: Bearer ${ADMIN_TOKEN}")
check "SUPER_ADMIN: GET /tenants" "200" "$STATUS"

STATUS=$(get_status "${API}/users" -H "Authorization: Bearer ${ADMIN_TOKEN}")
check "SUPER_ADMIN: GET /users" "200" "$STATUS"

STATUS=$(get_status "${API}/roles" -H "Authorization: Bearer ${ADMIN_TOKEN}")
check "SUPER_ADMIN: GET /roles" "200" "$STATUS"

STATUS=$(get_status "${API}/permissions" -H "Authorization: Bearer ${ADMIN_TOKEN}")
check "SUPER_ADMIN: GET /permissions" "200" "$STATUS"

STATUS=$(get_status "${API}/audit-logs" -H "Authorization: Bearer ${ADMIN_TOKEN}")
check "SUPER_ADMIN: GET /audit-logs" "200" "$STATUS"

# ─────────────────────────────────────────────────────────
# Test 4: TENANT_MEMBER cannot access tenant-admin resources
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [TENANT_MEMBER] Restricted access checks"

MEMBER_TOKEN=$(login "$MEMBER_EMAIL" "$MEMBER_PASSWORD")

if [ -z "$MEMBER_TOKEN" ]; then
  echo "  WARN: Member login failed (${MEMBER_EMAIL}) — trying to create a test member user via admin..."

  # Create a test member user
  CREATE_RESPONSE=$(curl -s -X POST "${API}/users" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
      "email":"rbac-test-member@fivucsas.local",
      "password":"Test@123",
      "firstName":"RBAC",
      "lastName":"TestMember",
      "role":"USER",
      "tenantId":"11111111-1111-1111-1111-111111111111"
    }')

  echo "  Create response: $CREATE_RESPONSE"
  MEMBER_TOKEN=$(login "rbac-test-member@fivucsas.local" "Test@123")
fi

if [ -n "$MEMBER_TOKEN" ]; then
  # TENANT_MEMBER should NOT be able to list tenants (tenant:read = admin-only)
  STATUS=$(get_status "${API}/tenants" -H "Authorization: Bearer ${MEMBER_TOKEN}")
  check "TENANT_MEMBER: GET /tenants (expect 403)" "403" "$STATUS"

  # TENANT_MEMBER should NOT be able to list all users beyond their scope
  # (user:read permission is checked — USER role has user.read so this may be 200 or 403 depending on impl)
  STATUS=$(get_status "${API}/roles" -H "Authorization: Bearer ${MEMBER_TOKEN}")
  check "TENANT_MEMBER: GET /roles (expect 403)" "403" "$STATUS"

  # TENANT_MEMBER should NOT be able to read audit logs
  STATUS=$(get_status "${API}/audit-logs" -H "Authorization: Bearer ${MEMBER_TOKEN}")
  check "TENANT_MEMBER: GET /audit-logs (expect 403)" "403" "$STATUS"

  # TENANT_MEMBER should NOT be able to create tenants
  STATUS=$(get_status -X POST "${API}/tenants" \
    -H "Authorization: Bearer ${MEMBER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"name":"Evil Tenant","slug":"evil","contactEmail":"evil@evil.local","maxUsers":1}')
  check "TENANT_MEMBER: POST /tenants (expect 403)" "403" "$STATUS"
else
  echo "  WARN: Could not get member token — skipping TENANT_MEMBER tests"
  FAIL=$(( FAIL + 4 ))
fi

# ─────────────────────────────────────────────────────────
# Test 5: Cross-tenant isolation check
# ─────────────────────────────────────────────────────────

echo ""
echo ">>> [Isolation] Cross-tenant resource access"

# Admin can read system tenant details
SYSTEM_TENANT_ID="00000000-0000-0000-0000-000000000000"
STATUS=$(get_status "${API}/tenants/${SYSTEM_TENANT_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}")
check "SUPER_ADMIN: GET /tenants/system" "200 404" "$STATUS" "system tenant may not exist at this UUID"

# Admin can read statistics
STATUS=$(get_status "${API}/statistics" -H "Authorization: Bearer ${ADMIN_TOKEN}")
check "SUPER_ADMIN: GET /statistics" "200" "$STATUS"

# ─────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════"
echo " RBAC Results: ${PASS} PASS, ${FAIL} FAIL"
echo "═══════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
