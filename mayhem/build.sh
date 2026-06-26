#!/usr/bin/env bash
#
# mayhem/build.sh — build PSn00bSDK's host-side fuzz harnesses + the functional test suite.
#
# PSn00bSDK targets two HOST tools (no PS1/MIPS cross-toolchain needed):
#   * elf2cpe  — ELF->CPE converter (tools/util/elf2cpe.c). A file-input target: it reads an ELF
#                from argv and writes a .cpe. (Has a real fixed-size stack buffer for program
#                headers — a productive fuzz target.)
#   * addfileentry — libFuzzer harness over FileListClass::AddFileEntry (tools/lzpack/filelist.cpp).
# Both compile from a handful of self-contained sources, so the build is fully air-gapped.
#
# Runs inside the commit image as `mayhem` in /mayhem. The base (ghcr.io/mayhemheroes/base) exports
# the build contract (CC/CXX/LIB_FUZZING_ENGINE/SANITIZER_FLAGS/STANDALONE_FUZZ_MAIN/SRC); we add
# DEBUG_FLAGS=-gdwarf-3 (DWARF<4 for Mayhem triage) on top.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DWARF must be < 4 (Mayhem triage can't read >=4); clang's plain -g emits DWARF-5, so be explicit.
# Put $DEBUG_FLAGS AFTER $SANITIZER_FLAGS so -gdwarf-3 wins over the base's -g.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the oracle build. Set via --build-arg to instrument
# the TEST build for source-coverage measurement.
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem

UTIL="$SRC/tools/util"
LZP="$SRC/tools/lzpack"

echo ">> [1/5] elf2cpe libFuzzer harness + standalone (clang + ASan+UBSan + DWARF<4)"
# elf2cpe is fuzzed IN-PROCESS via mayhem/fuzz_elf2cpe.c (libFuzzer) rather than as a file-input @@
# target: its stack-buffer overflow (prg_entry_count > 128 over prg_heads[128]) is trivially reachable,
# so as an mfuzz target Mayhem's corpus saturates with crashes and the post-run coverage finalization
# never completes (edges finalize to 0). libFuzzer reports edge coverage from in-process SanitizerCoverage
# during the run, which finalizes reliably (like the addfileentry target). The harness links elf2cpe.c
# with its main() renamed away (-Dmain) so convertELF()/in_file/out_file/quiet are reused verbatim.
# LSan off via a weak __asan_default_options (elf2cpe doesn't fclose on every error path).
ELF2CPE_EXTRA=
if printf '%s' "$SANITIZER_FLAGS" | grep -q address; then
  cat > /tmp/elf2cpe_asan_opts.c <<'EOF'
const char *__asan_default_options(void) { return "detect_leaks=0"; }
EOF
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -c /tmp/elf2cpe_asan_opts.c -o /tmp/elf2cpe_asan_opts.o
  ELF2CPE_EXTRA=/tmp/elf2cpe_asan_opts.o
fi
# Compile elf2cpe.c ONCE with its main renamed (so neither driver's main collides), then link that
# object into both the libFuzzer build and the standalone reproducer. -fsanitize=fuzzer-no-link is
# REQUIRED here: it adds SanitizerCoverage to the PARSER itself (separate TU) so libFuzzer sees the
# converter's edges — ASan/UBSan alone add zero sancov, leaving only the harness TU instrumented and
# coverage stuck at a handful of edges.
$CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -Dmain=elf2cpe_cli_main \
    -c "$UTIL/elf2cpe.c" -I"$UTIL" -o /tmp/elf2cpe_nomain.o
# fuzzer (libFuzzer engine provides main)
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_elf2cpe.c" /tmp/elf2cpe_nomain.o -I"$UTIL" $ELF2CPE_EXTRA \
    -o "$OUT/fuzz_elf2cpe"
# standalone reproducer (StandaloneFuzzTargetMain.c provides a run-once main; no -Dmain here)
$CC $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$STANDALONE_FUZZ_MAIN" "$SRC/mayhem/fuzz_elf2cpe.c" /tmp/elf2cpe_nomain.o -I"$UTIL" $ELF2CPE_EXTRA \
    -o "$OUT/fuzz_elf2cpe-standalone"

echo ">> [2/5] addfileentry libFuzzer harness"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_AddFileEntry.cpp" "$LZP/filelist.cpp" -I"$LZP" \
    -o "$OUT/fuzz_AddFileEntry"

echo ">> [3/5] addfileentry standalone reproducer (no libFuzzer runtime)"
# Compile the run-once driver as a C object first so its LLVMFuzzerTestOneInput ref keeps C linkage
# (clang++ would mangle it and miss the harness's extern "C" definition).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$SRC/mayhem/fuzz_AddFileEntry.cpp" "$LZP/filelist.cpp" /tmp/standalone_main.o -I"$LZP" \
    -o "$OUT/fuzz_AddFileEntry-standalone"

echo ">> [4/5] functional test oracle builds (NORMAL flags — independent of the sanitized build)"
# A clean elf2cpe the known-answer test drives, and the filelist unit selftest.
$CC -O2 $COVERAGE_FLAGS "$UTIL/elf2cpe.c" -I"$UTIL" -o "$OUT/elf2cpe-oracle"
$CXX -O2 $COVERAGE_FLAGS \
    "$SRC/mayhem/filelist_selftest.cpp" "$LZP/filelist.cpp" -I"$LZP" \
    -o "$OUT/filelist_selftest"

echo ">> [5/5] generate the deterministic ELF test fixture (build time)"
mkdir -p "$OUT/test-fixtures"
# The generator is NOT a fuzz/oracle binary — it just materializes a known MIPS-LE ELF executable so
# test.sh has a stable known-answer input. Built + run here at build time (no network).
$CC -O2 "$SRC/mayhem/gen_elf_fixture.c" -o /tmp/gen_elf_fixture
/tmp/gen_elf_fixture "$OUT/test-fixtures/sample.elf"

echo ">> build.sh done"
ls -l "$OUT"/fuzz_elf2cpe "$OUT"/fuzz_elf2cpe-standalone \
      "$OUT"/fuzz_AddFileEntry "$OUT"/fuzz_AddFileEntry-standalone \
      "$OUT"/elf2cpe-oracle "$OUT"/filelist_selftest "$OUT"/test-fixtures/sample.elf
