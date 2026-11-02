#!/usr/bin/env bash
# Assert that each named integration-test class really EXECUTED tests.
#
# Usage: assert-its-executed.sh <surefire-reports-dir> <ITClass>...
#
# A class counts as executed when, summed over its top-level report and every
# JUnit 5 @Nested shard (TEST-...<IT>$Inner.xml), tests - skipped >= 1.
#
# Why "minus skipped": a class-level @EnabledIfEnvironmentVariable that is not
# satisfied (e.g. RUN_INTEGRATION unset) does NOT produce tests="0". Surefire
# 3.5.x + JUnit 5 writes one skipped testcase per method, i.e. tests="N"
# skipped="N". Counting only tests= would let that silent skip pass.
set -euo pipefail

reports=${1:?usage: $0 <surefire-reports-dir> <ITClass>...}
shift
[ "$#" -ge 1 ] || { echo "usage: $0 <surefire-reports-dir> <ITClass>..." >&2; exit 2; }

attr() { # attr <name> <file>: first value of the attribute on the <testsuite> element
  grep -oP "<testsuite\b[^>]*\b$1=\"\K[0-9]+" "$2" | head -1 || true
}

fail=0
for it in "$@"; do
  shopt -s nullglob
  matches=( "$reports"/TEST-*."$it".xml "$reports"/TEST-*."$it"\$*.xml )
  shopt -u nullglob
  if [ "${#matches[@]}" -eq 0 ]; then
    echo "::error::$it produced no surefire report: it did NOT run (RUN_INTEGRATION gating or -Dtest filter broke)"
    fail=1
    continue
  fi
  tests=0 skipped=0
  for m in "${matches[@]}"; do
    t=$(attr tests "$m"); s=$(attr skipped "$m")
    tests=$((tests + ${t:-0})); skipped=$((skipped + ${s:-0}))
  done
  executed=$((tests - skipped))
  if [ "$executed" -lt 1 ]; then
    echo "::error::$it executed 0 tests ($tests reported, $skipped skipped; reports: ${matches[*]})"
    fail=1
  else
    echo "OK: $it executed $executed test(s) ($skipped skipped) across ${#matches[@]} report(s)"
  fi
done
exit $fail
