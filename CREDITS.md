# Credits

## Upstream
* Repository: https://github.com/SachinVin/TeakLite-SLEIGH, commit `c93545bd37374557722d9c8a00c5f6052f3150a0`
  ("implement add and sub", 2023-12-03). License: MIT (`LICENSE`, Copyright (c) 2023 SachinVin).
* Original author (git log): SachinVin <sachinvinayak2000@gmail.com>, one commit. Language ID `teak:LE:16:default` and the
  processor name `TeakLite` are upstream's and unchanged. The upstream constructor list, token fields and operand names were
  mechanically derived from Teakra's decoder table (`utils/teakra_parser.py`, `utils/teakra_opcodes.py`).

## Teakra (MIT)
* https://github.com/wwylele/teakra, Copyright (c) 2018 Weiyi Wang, commit `3d697a18df504f4677b65129d9ab14c7c597e3eb`;
  license text in `LICENSE.teakra`.
* `tools/teak_insts.json` is the encoding table of `src/decoder.h` (names, opcodes, operand kinds and positions, excluded
  values), extracted by `tools/extract_teakra_table.py`. The operand encodings and the instruction semantics in
  `tools/teak_sem.py` and `data/languages/teak_macros.sinc` were written from `src/interpreter.h`, `src/operand.h` and
  `include/teakra/impl/register.h` (MIT: used as a semantic reference), cross-checked with GBATEK.
* Teakra is also the reference tool of the tests (built from the pinned commit and driven by `test/teakra/{dis,step}.cpp`).
  The four DSP1 programs used as real code are Teakra's own hardware test programs (`hwtest/*/data/cdc.bin`, MIT).
* Documentation: Martin Korth's GBATEK (http://problemkaputt.de/gbatek.htm).

## Other implementations noticed (not used)
* https://github.com/PSI-Rockin/ghidra-teak-dsp (MIT, WIP: lacks modulo / bit-reverse / saturation and many instructions;
  has its own DSP1 loader).
* https://github.com/Pokechu22/ghidra-xpertteak-lang (no usable license file, only Ghidra's template `LICENSE.txt`).

## What Ghidra-Rare changed
1. Replaced the hand-edited constructor files (`teak.sinc`, `alb.sinc`, `alm_alu.sinc`, `moda.sinc`) with a generator
   (`tools/gen_teak.py`, `tools/teak_lib.py`, `tools/teak_sem.py`) that writes `teak_tokens.sinc`, `teak_tables.sinc` and
   `teak_insts.sinc`; hand-written macros are in `teak_macros.sinc`. All 443 encodings, no `unimpl`.
2. New register model: flag and mode bytes (single storage), views composed on read / decomposed on write for `st0-2`,
   `stt0-2`, `mod0-3`, `icr`; real `ar0/ar1/arp0-3/cfgi/cfgj/mod2`; block-repeat stack, shadows for `cntx` and `banke/bankr`.
3. Address generation (`[rN++s]`, `[arrnX+arsY]`, arp pairs) with the optional modulo / bit-reverse / step-2 model, language
   variant `teak:LE:16:modulo`.
4. Unconditional forms of conditional instructions get their own constructors, so `br always` / `ret` end basic blocks.
5. `rep` implemented with a delay slot loop. `pspec`: removed the overlapping RAM-X/RAM-Y blocks and added the AMOD context;
   removed the stale 6502 manual index.
6. DSP1 firmware loader (`src/main/java/.../Dsp1Loader.java`).
7. Tests (`test/`), build files (`build.gradle`, `extension.properties`), README and this documentation.
