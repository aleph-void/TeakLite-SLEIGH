#!/usr/bin/env bash
# run-step.sh <language-id> <cases> <out> <watchlist>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/teak-step.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 64 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader -loader-baseAddr 0x0 -processor "$1" -noanalysis -scriptPath "$HERE" \
 -postScript TeakStep.java "$(readlink -f "$2")" "$(readlink -m "$3")" "$(readlink -f "$4")" ${5:+"$(readlink -f "$5")"} -deleteProject > "$PROJ/log.txt" 2>&1 || { tail -30 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $3 ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head >&2; exit 1; }
