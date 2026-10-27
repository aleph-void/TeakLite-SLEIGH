#!/usr/bin/env bash
# test/fetch-real.sh <workdir>: downloads the four DSP1 test programs of Teakra's hardware testers (MIT, by wwylele) at a pinned
# commit and checks their SHA-256.  Nothing here is committed.  Writes <workdir>/real/*.dsp1.
set -euo pipefail
W=$(mkdir -p "$1" && cd "$1" && pwd)
mkdir -p "$W/real"
PIN=3d697a18df504f4677b65129d9ab14c7c597e3eb
while read -r name sha; do
	f="$W/real/$name.dsp1"
	if [[ ! -f $f ]]; then
		curl -sSfL -o "$f" "https://raw.githubusercontent.com/wwylele/teakra/$PIN/hwtest/$name/data/cdc.bin"
	fi
	echo "$sha  $f" | sha256sum -c --quiet - || { echo "SHA-256 mismatch for $name" >&2; exit 1; }
done <<LIST
dsptester 8ca5542b078de7b580c16c0773cc5202cab0ef93ab628d0b6aa6f875538cb471
dspmemorytester a026d32763280fe31e2abd7730d0475668f179579a3bbce62462502931f65073
dspvictester 0e27853be5318f25e853c0113028393a601dc81b448d82aa7824758f10202480
dspapbptester 2f3172081622e0f299c95bc9a4dcbbd36588d3910c967fde856999d69f5d1ddd
LIST
echo "fetched $(ls "$W/real" | wc -l) images into $W/real"
