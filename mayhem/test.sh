#!/usr/bin/env bash
#
# rtpproxy/mayhem/test.sh — RUN the RTCP-parse golden oracle (built by mayhem/build.sh against the
# instrumented librtpproxy) and emit a CTRF summary. exit 0 iff no case failed.
#
# PATCH-grade oracle: /mayhem/rtcp_oracle drives the SAME rtcp2json() the fuzz_rtcp_parser harness
# fuzzes, feeding known RTCP SR/RR packets and asserting BYTE-EXACT JSON (SSRC values, RTCP type,
# report_count, sender packet/octet counts) plus the reject paths (bad version, short buffer). A
# no-op / exit(0) patch to rtcp2json cannot reproduce that JSON, so it cannot pass. This script only
# RUNS the pre-built binary; it never compiles.
#
# rtpproxy's full automated suite (tests/, libre/, libxxHash/ ...) needs live UDP/TCP sockets, control
# sockets and spawned helpers — not self-contained in a build sandbox — so we run this focused golden
# oracle over the fuzzed RTCP parse path instead.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

ORACLE="/mayhem/rtcp_oracle"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "rtcp2json-oracle" 0 1 0; exit 2
fi

echo "=== running rtcp2json golden oracle ==="
out="$("$ORACLE" 2>&1)"; rc=$?
echo "$out"

# Prefer the oracle's own CTRF counts (authoritative). Fall back to the exit code if absent.
ctrf="$(printf '%s\n' "$out" | grep -m1 '^CTRF ' | sed 's/^CTRF //')"
if [ -n "$ctrf" ]; then
  PASSED=$(printf '%s' "$ctrf" | python3 -c 'import sys,json; print(json.load(sys.stdin)["results"]["summary"]["passed"])' 2>/dev/null || echo "")
  FAILED=$(printf '%s' "$ctrf" | python3 -c 'import sys,json; print(json.load(sys.stdin)["results"]["summary"]["failed"])' 2>/dev/null || echo "")
fi
if [ -z "${PASSED:-}" ] || [ -z "${FAILED:-}" ]; then
  echo "could not parse oracle CTRF; using exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "rtcp2json-oracle" 1 0 0; exit 0; }
  emit_ctrf "rtcp2json-oracle" 0 1 0; exit 1
fi

emit_ctrf "rtcp2json-oracle" "$PASSED" "$FAILED" 0
