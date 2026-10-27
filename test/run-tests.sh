#!/usr/bin/env bash
# Runs every TeakLite check that needs no non-redistributable input.
#
#   GHIDRA_INSTALL_DIR=<Ghidra with this module linked into Ghidra/Processors/TeakLite> \
#     test/run-tests.sh [--real] [--per-op N] <workdir>
#
# Needs g++ and git (teakra is cloned at a pinned commit and built as a black box), python3, curl (--real).  --per-op is the
# number of random states per opcode in the differential runs (default 1; the recorded results use 2).  --real also fetches the
# four MIT-licensed DSP1 test programs of Teakra and needs the extension jar in lib/ (tools/build-module.sh puts it in the zip).
# Exit status 0 only if every step passes.
set -uo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(dirname "$HERE")
REAL=0; PER=1
while [[ ${1:-} == --* ]]; do
	case $1 in --real) REAL=1; shift ;; --per-op) PER=$2; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;; esac
done
W=$(mkdir -p "$1" && cd "$1" && pwd)
export TMPDIR=${TMPDIR:-$W}
fail=0
step() { echo "== $*"; }
ok() { "$@" || { echo "FAILED: $*"; fail=1; }; }

step "the generator reproduces the checked-in SLEIGH"
mkdir -p "$W/gen"
python3 -I "$MOD/tools/gen_teak.py" "$W/gen" 2>&1 | tail -1
for f in teak_tokens teak_tables teak_insts; do ok diff -q "$W/gen/$f.sinc" "$MOD/data/languages/$f.sinc"; done

step "the spec compiles (sleigh -l: no unresolved pattern conflicts)"
out=$("$GHIDRA_INSTALL_DIR/support/sleigh" -l "$MOD/data/languages/teak.slaspec" 2>&1)
if grep -q "ERROR" <<<"$out"; then echo "$out" | grep ERROR | head; echo "FAILED: teak.slaspec"; fail=1; else echo "teak.slaspec compiles, no conflicts"; fi

step "reference tool: teakra (MIT), built from a pinned commit"
ok "$HERE/fetch-oracles.sh" "$W"
O="$W/oracle"
DIS=$O/teakra-dis; STEP=$O/teakra-step

step "decode: all 65,536 opcode words vs teakra's decoder (validity and length)"
python3 -I - "$W/ops.txt" <<'PY'
import sys
open(sys.argv[1], 'w').write(''.join('%x 1234\n' % o for o in range(65536)))
PY
"$DIS" < "$W/ops.txt" > "$W/teakra_all.txt"
python3 -I - "$W/cases.txt" <<'PY'
import sys
open(sys.argv[1], 'w').write(''.join('%02x%02x3412\n' % (o & 255, o >> 8) for o in range(65536)))
PY
ok "$HERE/dis.sh" teak:LE:16:default "$W/cases.txt" "$W/g_all.txt"
ok python3 -I "$HERE/decode_cmp.py" "$W/teakra_all.txt" "$W/g_all.txt"

step "every constructor and table entry is reached (default and AMOD=1 together)"
"$HERE/every-entry.sh" teak:LE:16:default "$W/cases.txt" "$W/ee1.txt" >/dev/null
"$HERE/every-entry.sh" teak:LE:16:default "$W/cases.txt" "$W/ee2.txt" AMOD=1 | tail -1
n=$(comm -12 <(grep NOT "$W/ee1.txt" | sort) <(grep NOT "$W/ee2.txt" | sort) | wc -l)
echo "constructors reached by neither: $n"
((n == 0)) || { fail=1; echo "FAILED: unreached constructors"; }

step "p-code: hand-computed emulator cases (and deliberately wrong expectations)"
ok "$HERE/emu-test.sh" "$HERE/emu/cases.txt" "$W/emu"

step "p-code vs teakra: one instruction from random states, every opcode (rep is checked by hand, see emu/cases.txt)"
DT=(python3 -I "$HERE/difftest.py" "$STEP" "$DIS" "$GHIDRA_INSTALL_DIR" --skip-fam rep --per-op "$PER")
ok "${DT[@]}" "$W/dt-default" --seed 21
ok "${DT[@]}" "$W/dt-modulo" --amod --seed 22
ok "${DT[@]}" "$W/dt-brev" --brev --seed 23
step "the differential test can fail (a deliberately wrong expectation must be reported)"
ok python3 -I "$HERE/difftest.py" "$STEP" "$DIS" "$GHIDRA_INSTALL_DIR" "$W/dt-self" --self-check --fam or,add --limit 40

if ((REAL)); then
	step "real programs: Teakra's DSP1 test programs through the DSP1 loader"
	ok "$HERE/fetch-real.sh" "$W"
	ok "$HERE/real-check.sh" "$W" "$DIS"
fi
((fail)) && { echo "SOME CHECKS FAILED"; exit 1; }
echo "ALL CHECKS PASSED"
