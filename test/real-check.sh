#!/usr/bin/env bash
# test/real-check.sh <workdir> <teakra-dis>: imports every <workdir>/real/*.dsp1 headless WITHOUT forcing a language (the DSP1
# loader names the language), reports instruction / function / bookmark / decompiler counts and compares the listing with
# Teakra's disassembly of the same words.  Needs the extension's jar in the module's lib/ (see run-tests.sh).
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(cd "$1" && pwd); DIS=$2
rc=0
for f in "$W"/real/*.dsp1; do
	n=$(basename "$f" .dsp1)
	P=$(mktemp -d "${TMPDIR:-/tmp}/teak-real.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$P" p -import "$f" -scriptPath "$HERE" \
		-postScript RealCheck.java "$W/real/$n" -deleteProject >"$P/log.txt" 2>&1 || { tail -30 "$P/log.txt"; rc=1; }
	grep -E "REAL:|decompile failure|bad instruction" "$P/log.txt" | sed 's/.*Script.java> //; s/ (GhidraScript)//' || true
	grep -q "Using Loader: Nintendo DSP1" "$P/log.txt" || { echo "FAILED: $n was not recognised by the DSP1 loader"; rc=1; }
	grep -q " bad_instruction_bookmarks=0 error_bookmarks=0 decompile_failures=0" "$P/log.txt" || { echo "FAILED: $n has bookmarks or decompiler failures"; rc=1; }
	rm -rf "$P"
	python3 -I "$HERE/real_check.py" "$DIS" "$f" "$W/real/$n.lst" || rc=1
done
exit $rc
