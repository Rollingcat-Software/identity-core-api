#!/usr/bin/env bash
# Fault-injection self-test for assert-its-executed.sh. Fixtures under fixtures/
# are real Surefire 3.5.3 / JUnit 5.11.4 reports from a probe project whose ITs
# carry the same class-level @EnabledIfEnvironmentVariable(RUN_INTEGRATION) as
# the real ITs (healthy = variable set; unset_variable = variable unset).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
gate="$here/assert-its-executed.sh"
its=(CrossTenantIsolationIT TenantSwitcherIsolationIT)
status=0
expect() { # expect <scenario> <expected-exit>
  "$gate" "$here/fixtures/$1" "${its[@]}" >/dev/null 2>&1
  got=$?
  if [ "$got" -eq "$2" ]; then echo "PASS $1 (exit $got)"; else echo "FAIL $1: expected exit $2, got $got"; status=1; fi
}
expect healthy 0
expect unset_variable 1
expect missing_report 1
expect nested_only 0
expect all_zero 1
exit $status
