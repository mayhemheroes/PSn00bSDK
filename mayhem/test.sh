#!/usr/bin/env bash
#
# mayhem/test.sh — RUN PSn00bSDK's host-tool functional oracle (built by mayhem/build.sh).
#
# Two behavioral, assertion-based tests (NOT "exit 0 / didn't crash"):
#   1. elf2cpe known-answer: convert a fixed MIPS-LE ELF and byte-compare the produced .cpe against
#      the independently-computed expected output. (A no-op/exit(0) elf2cpe produces no file → FAIL.)
#   2. filelist selftest: assert FileListClass::AddFileEntry stores entries with the right fields.
# Both drive project binaries, so the anti-reward-hack sabotage check (which neuters project binaries
# to exit(0)) makes this script FAIL — exactly as a behavioral oracle should.
#
# Emits a CTRF (https://ctrf.io) summary and exits non-zero iff failed>0.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"
OUT=/mayhem

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

ELF2CPE="$OUT/elf2cpe-oracle"
SELFTEST="$OUT/filelist_selftest"
FIXTURE="$OUT/test-fixtures/sample.elf"

# Fail loudly if build.sh didn't produce the runners (a build bug — do NOT rebuild here).
for f in "$ELF2CPE" "$SELFTEST" "$FIXTURE"; do
  if [ ! -e "$f" ]; then
    echo "ERROR: missing $f — mayhem/build.sh did not produce the test artifacts" >&2
    emit_ctrf "psn00bsdk-tools" 0 1
    exit 1
  fi
done

passed=0; failed=0

# --- test 1: elf2cpe ELF->CPE known-answer ----------------------------------------------------
GOT=/tmp/elf2cpe_out.cpe
EXP=/tmp/elf2cpe_expected.cpe
rm -f "$GOT" "$EXP"

# Compute the expected CPE independently (python3 is a system binary — spared by the sabotage check).
python3 - "$EXP" <<'PY'
import sys, struct
ENTRY = 0x80010000
data  = bytes([0xDE, 0xAD, 0xBE, 0xEF])
out  = b"CPE" + bytes([0x01])
out += bytes([0x08, 0x00])                                  # select unit 0
out += bytes([0x03, 0x90, 0x00]) + struct.pack("<I", ENTRY) # entrypoint chunk
out += bytes([0x01]) + struct.pack("<I", ENTRY) + struct.pack("<I", len(data)) + data  # load chunk
out += bytes([0x00])                                        # EOF chunk
open(sys.argv[1], "wb").write(out)
PY

"$ELF2CPE" -q "$FIXTURE" "$GOT" >/tmp/elf2cpe.log 2>&1 || true
if [ -f "$GOT" ] && cmp -s "$GOT" "$EXP"; then
  echo "PASS test1: elf2cpe ELF->CPE matches known-answer output"
  passed=$((passed+1))
else
  echo "FAIL test1: elf2cpe output differs from expected (or was not produced)"
  echo "  got:      $(wc -c < "$GOT" 2>/dev/null || echo MISSING) bytes"
  echo "  expected: $(wc -c < "$EXP") bytes"
  failed=$((failed+1))
fi

# --- test 2: filelist AddFileEntry behavioral selftest ----------------------------------------
if out="$("$SELFTEST" 2>&1)" && printf '%s' "$out" | grep -q '^SELFTEST_OK$'; then
  echo "PASS test2: FileListClass::AddFileEntry stores entries correctly"
  passed=$((passed+1))
else
  echo "FAIL test2: filelist selftest did not report SELFTEST_OK"
  printf '%s\n' "$out"
  failed=$((failed+1))
fi

emit_ctrf "psn00bsdk-tools" "$passed" "$failed"
