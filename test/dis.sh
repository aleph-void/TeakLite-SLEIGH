#!/usr/bin/env bash
# test/dis.sh <language-id> <cases.txt> <out.txt>   (GHIDRA_INSTALL_DIR set)
# Decodes each hex string in cases.txt (placed at 0x1000) and writes "<hex> <len> <text>".
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1; IN=$(readlink -f "$2"); OUT=$(readlink -m "$3"); shift 3
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/pdk-dis.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 64 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-loader-baseAddr 0x1000 -processor "$LANG_ID" -noanalysis -scriptPath "$HERE" \
	-postScript DisCases.java "$IN" "$OUT" "$@" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -n ${PDK_DEBUG:-} ]] && grep "BAD " "$PROJ/log.txt" | head -5 >&2
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
