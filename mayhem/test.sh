#!/usr/bin/env bash
#
# mayhem/test.sh — RGFW functional checks, run against a private Xvfb server (built by build.sh):
#  * upstream's tests/clipboard.c: writes the CLIPBOARD and asserts RGFW reads back the same bytes;
#    its stdout is also diffed against a golden file;
#  * known-answer tests over the three X11 input paths: each harness built with RGFW_MAYHEM_SELFTEST
#    (normal flags) prints what RGFW delivered for each seed (dropped paths, drag/close events,
#    clipboard text, clipboard replies served,
#    key/button events and window state, converted pixels and icons), and the output must match mayhem/tests/expected/<name>.txt exactly.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
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

OUT="$SRC/mayhem/out"
EXP="$SRC/mayhem/tests/expected"
for b in test_clipboard fuzz_xdnd_drop-selftest fuzz_xdnd_events-selftest fuzz_clipboard_read-selftest fuzz_clipboard_serve-selftest fuzz_x11_events-selftest fuzz_image_api-selftest; do
  [ -x "$OUT/$b" ] || { echo "missing $OUT/$b — run mayhem/build.sh first" >&2; emit_ctrf rgfw-x11-kat 0 1; exit 1; }
done

# A private X server for the whole suite; Xvfb picks a free display and reports it on fd 3.
tmp="$(mktemp -d)"
trap 'kill "$XVFB_PID" 2>/dev/null; rm -rf "$tmp"' EXIT
Xvfb -displayfd 3 -nolisten tcp -screen 0 640x480x24 3>"$tmp/display" >/dev/null 2>&1 &
XVFB_PID=$!
for _ in $(seq 100); do [ -s "$tmp/display" ] && break; sleep 0.1; done
[ -s "$tmp/display" ] || { echo "Xvfb did not start" >&2; emit_ctrf rgfw-x11-kat 0 1; exit 1; }
export DISPLAY=":$(head -n1 "$tmp/display")"

passed=0; failed=0
check() { # check <name> <command...>: run, compare stdout with $EXP/<name>.txt
  local name="$1"; shift
  if "$@" >"$tmp/$name.out" 2>"$tmp/$name.err" && diff -u "$EXP/$name.txt" "$tmp/$name.out"; then
    echo "PASS $name"; passed=$((passed + 1))
  else
    echo "FAIL $name"; sed -n '1,20p' "$tmp/$name.err"; failed=$((failed + 1))
  fi
}

check test_clipboard "$OUT/test_clipboard"
for t in fuzz_xdnd_drop fuzz_xdnd_events fuzz_clipboard_read fuzz_clipboard_serve fuzz_x11_events fuzz_image_api; do
  for seed in "$SRC/mayhem/$t/testsuite"/*; do
    check "$t.$(basename "$seed")" "$OUT/$t-selftest" "$seed"
  done
done

emit_ctrf rgfw-x11-kat "$passed" "$failed"
