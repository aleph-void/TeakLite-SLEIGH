# Ghidra-Rare notes: TeakLite (Nintendo DSi / 3DS DSP, Teak / TeakLite II)

Source: SachinVin/TeakLite-SLEIGH (MIT), finished and verified here. Credits: [CREDITS.md](CREDITS.md).
Languages: `teak:LE:16:default` (address registers are plain counters) and `teak:LE:16:modulo` (modulo, bit-reversed and
Teak-style step addressing in p-code; the context bit `AMOD` selects it per region). Extension zips for Ghidra 12.1.3, 12.1.4
and 12.2 build with `tools/build-module.sh --standard --name TeakLite`.

The specification is generated: `tools/gen_teak.py` (encodings from `tools/teak_insts.json`, semantics in `tools/teak_sem.py`,
macros in `data/languages/teak_macros.sinc`). A DSP1 firmware loader is included.

## Testing

`GHIDRA_INSTALL_DIR=<Ghidra with the module in Ghidra/Processors/TeakLite> test/run-tests.sh [--real] [--per-op N] <workdir>`

Reference tool: Teakra (MIT; pinned commit built by `test/fetch-oracles.sh`), used as a black box through `test/teakra/dis.cpp`
(disassembler) and `test/teakra/step.cpp` (one instruction from a given state). No second independent Teak tool exists
(MAME has no Teak core); semantics also follow GBATEK.

## Results

| Check | Result |
|---|---|
| Build | `sleigh -l` clean (no pattern conflicts) on 12.1.4; release zips built for 12.1.3, 12.1.4, 12.2; `.sla` about 320 KB |
| Decode | all 65,536 opcode words vs Teakra: 0 differ in validity or length (65,395 valid, 141 invalid on both sides) |
| Every entry | every constructor and table entry reached (default and `AMOD=1` together): 0 unreached |
| Hand-computed emulator cases | 30/30 (default), 3/3 (modulo); a deliberately wrong expectation is detected in both languages |
| p-code vs Teakra, default language | every opcode, 2 random states each (130,492 runs, `rep` excluded): 129,075 identical, 1,409 undefined in Teakra (asserts), 8 differences (below) |
| p-code vs Teakra, modulo language | random modulo/step-mode/cmd/stp16/epi/epj state: 128,104 identical, 2,384 Teakra-undefined, 4 differences (below) |
| p-code vs Teakra, bit-reversed addressing | 64,326 identical, 915 Teakra-undefined, 5 differences (below) |
| The differential test can fail | a deliberately corrupted expectation is reported (`--self-check`) |
| Real code | the 4 DSP1 test programs of Teakra (MIT, pinned URL + SHA-256, `test/fetch-real.sh`) import through the loader without forcing a language: 230 instructions, 21 functions, 0 bad-instruction bookmarks, 0 error bookmarks, 0 decompile failures, all 230 instructions agree with Teakra on validity and length |

The 8 + 4 + 5 differences, all explained:
* `tstb stt0/stt1, #imm16` (3): Teakra shifts by the whole 16-bit immediate (undefined behaviour in C++ for counts of 32 or
  more); the module uses the low 4 bits like the other `tstb` forms. Unverified on hardware.
* `movp Ax, Register` (7): the program address comes from the accumulator and falls outside the 0x3000-word window that
  both sides are initialised with, so Teakra reads 0 where the emulator reads other code. Test-window artefact.
* `cbs` with arp registers in bit-reversed mode (4): Teakra stores the raw (not bit-reversed) Rn value in `mixp`; the
  module stores the reversed address. Remaining; only with bit-reversed R0.. and `cbs`.
* `rep`: the module folds the repeated instruction into `rep` (delay slot loop), Teakra runs it per cycle; checked by
  a hand-computed case instead.

## Known gaps

Fixed from the original: 363 `unimpl` constructors, no saturation, no step/modulo/bit-reverse, fake `st0-2`/`stt`/`mod`
registers, overlapping default memory blocks, stale 6502 manual index.

Remaining, with reasons:
* `bkrep`: sets up the block-repeat stack, but Ghidra cannot express the implicit jump back at the loop end address.
* Interrupts, DMA, MMIO behaviour, `idle`, timers, APBP: hardware state outside the processor spec.
* `trap` is a user op; `retd`, `retid`, `retidc` are modelled as returns; `mov dvm` forms do nothing. Teakra itself leaves
  these undefined.
* `prpage`/program pages above 18 bits are stored but not used for fetches.
* Semantics follow Teakra, which carries its own TODOs (step-2 modes with offsets, `-1` offset with modulo is undefined there
  and plain here); nothing is compared with real silicon.
* The default language ignores modulo/bit-reverse/step-2 modes; select `teak:LE:16:modulo` or set `AMOD` for code using them.
* Calling convention in `teak.cspec` is upstream's and unverified (no compiler output available).
* The DSP1 loader ignores the filter segment and does not check hashes.

## Confirmed reference-tool bugs
* Teakra's disassembler prints `[ERROR]36..39` for `ext0..ext3` (register names missing); `[ERROR]52` marks reserved
  register encodings.
