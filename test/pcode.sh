#!/usr/bin/env bash
# test/pcode.sh <language-id> <hex word> ...   print the p-code of instruction words (development aid)
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1; shift
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/pdk-pc.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 65536 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-loader-baseAddr 0 -processor "$LANG_ID" -noanalysis -scriptPath "$HERE" \
	-postScript PcodeDump.java "$@" -deleteProject 2>&1 | grep "PcodeDump.java>" | sed 's/.*PcodeDump.java> //; s/ (GhidraScript)//'
