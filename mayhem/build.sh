#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# RGFW is a single header: each harness is one translation unit that defines RGFW_IMPLEMENTATION and
# includes RGFW.h, so compiling the harness with $SANITIZER_FLAGS instruments the whole library.
# The X11 backend is the Linux default; libX11/libXrandr come from apt (pinned via SOURCE_DATE_EPOCH).
# Xcursor/Xi/Xext are loaded by RGFW at runtime through dlopen.
X11_LIBS="-lXrandr -lX11 -ldl -lpthread -lm"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT"
HARNESSES="fuzz_xdnd_drop fuzz_xdnd_events fuzz_clipboard_read fuzz_clipboard_serve fuzz_x11_events fuzz_image_api"

# LeakSanitizer off at build time (docs: leaks are not the target bug class).
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OUT/lsan_off.o"

for h in $HARNESSES; do
  # 1+2) libFuzzer binary and standalone reproducer, project + harness instrumented.
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I"$SRC" \
      "$SRC/mayhem/harnesses/$h.c" "$OUT/lsan_off.o" $X11_LIBS -o "/mayhem/$h"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC" "$STANDALONE_FUZZ_MAIN" \
      "$SRC/mayhem/harnesses/$h.c" "$OUT/lsan_off.o" $X11_LIBS -o "/mayhem/$h-standalone"
  # 3) Known-answer test build with NORMAL flags (no sanitizers): the same harness with
  #    RGFW_MAYHEM_SELFTEST, which prints what RGFW delivered; mayhem/test.sh diffs it.
  # shellcheck disable=SC2086
  $CC -O1 $COVERAGE_FLAGS -DRGFW_MAYHEM_SELFTEST -I"$SRC" "$STANDALONE_FUZZ_MAIN" \
      "$SRC/mayhem/harnesses/$h.c" $X11_LIBS -o "$OUT/$h-selftest"
done

# fuzz_clipboard_read is fuzzed by Mayhem as an AFL target (one process per input), not as the libFuzzer
# binary: RGFW_readClipboardPtr reads data[size - 1] before checking size, so ANY empty CLIPBOARD
# property crashes it (mayhem/fuzz_clipboard_read/known-findings/empty-property). From an empty corpus
# libFuzzer reaches that within a handful of executions, stops at the first crash, and so fails
# Mayhem's in-process "fuzz for 5 iterations" start-up probe on every run. The AFL front end runs the
# same harness code (RGFW_MAYHEM_AFL selects main() instead of the libFuzzer entry points), project
# and harness instrumented by afl-clang-fast with the same sanitizers; the libFuzzer binary above stays
# for local fuzzing. AFL targets are their own reproducer (no -standalone).
# shellcheck disable=SC2086
# fuzz_clipboard_serve and fuzz_x11_events are fuzzed the same way, for the same reason: an odd-length
# ATOM_PAIR list (RGFW_XHandleClipboardSelection), a button number above 7 (RGFW's mouse-button state)
# or a format-8 _NET_WM_STATE (RGFW_window_isFloating) crash within libFuzzer's start-up probe.
for h in fuzz_clipboard_read fuzz_clipboard_serve fuzz_x11_events; do
  # shellcheck disable=SC2086
  AFL_QUIET=1 afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS -DRGFW_MAYHEM_AFL -I"$SRC" \
      "$SRC/mayhem/harnesses/$h.c" "$OUT/lsan_off.o" $X11_LIBS -o "/mayhem/$h-afl"
done

# Upstream's own clipboard round-trip test (asserts RGFW reads back what it wrote), normal flags.
# shellcheck disable=SC2086
$CC -O1 $COVERAGE_FLAGS -I"$SRC" "$SRC/tests/clipboard.c" $X11_LIBS -o "$OUT/test_clipboard"
