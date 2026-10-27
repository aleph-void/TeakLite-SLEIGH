#!/usr/bin/env bash
# test/fetch-oracles.sh <workdir>: clones teakra (MIT, pinned commit), builds its disassembler and interpreter into the
# two black-box drivers test/teakra/dis.cpp (disassembler) and test/teakra/step.cpp (one instruction from a given state).
# Writes <workdir>/oracle/{teakra-dis,teakra-step}.
set -euo pipefail
W=$(mkdir -p "$1" && cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
PIN=3d697a18df504f4677b65129d9ab14c7c597e3eb
O="$W/oracle"
mkdir -p "$O"
if [[ -x $O/teakra-dis && -x $O/teakra-step ]]; then exit 0; fi
if [[ ! -d $O/teakra-src ]]; then
	git clone -q https://github.com/wwylele/teakra.git "$O/teakra-src"
	git -C "$O/teakra-src" checkout -q "$PIN"
fi
S=$O/teakra-src/src
INC="-I$O/teakra-src/include -I$O/teakra-src/include/teakra -I$O/teakra-src/include/teakra/impl -I$S"
mkdir -p "$O/obj"
for f in ahbm apbp btdmp disassembler dma timer memory_interface mmio parser processor teakra test_generator; do
	g++ -O2 -std=c++17 -pthread $INC -c "$S/$f.cpp" -o "$O/obj/$f.o"
done
g++ -O2 -std=c++17 $INC "$HERE/teakra/dis.cpp" "$S/disassembler.cpp" -o "$O/teakra-dis"
g++ -O2 -std=c++17 -pthread $INC "$HERE/teakra/step.cpp" "$O"/obj/*.o -o "$O/teakra-step"
echo "built $O/teakra-dis and $O/teakra-step from teakra $PIN"
