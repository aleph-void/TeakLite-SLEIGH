#!/usr/bin/env python3
"""Compare a Ghidra listing of a DSP1 image (RealCheck.java's .lst) with teakra's disassembly of the same words.
usage: real_check.py <teakra-dis> <image.dsp1> <listing.lst>"""
import struct, subprocess, sys, re
dis, img, lst = sys.argv[1:4]
b = open(img, 'rb').read()
words = {}
for i in range(b[0x10e]):
    off, addr, sz, pa, pb, pc, mt = struct.unpack_from('<IIIBBBB', b, 0x120 + i * 0x30)
    if mt == 2: continue
    for k in range(sz // 2):
        words[addr + k] = int.from_bytes(b[off + 2 * k:off + 2 * k + 2], 'little')
L = {}
for l in open(lst):
    a, w, t = l.rstrip('\n').split(' ', 2)
    L[int(a, 16)] = (len(w) // 4, t)
inp = ''.join('%x %x\n' % (words[a], words.get(a + 1, 0)) for a in sorted(L))
out = subprocess.run([dis], input=inp, capture_output=True, text=True).stdout.splitlines()
same = bad = 0
for a, line in zip(sorted(L), out):
    h, t = line.split('\t', 1)
    need = int(h.split()[2])
    glen, gtext = L[a]
    tvalid = '[ERROR]' not in re.sub(r'\[ERROR\]3[6-9]', 'ext', t)
    if tvalid and glen == 1 + need:
        same += 1
    else:
        bad += 1
        print('DIFF %05x ghidra=%s teakra=%s' % (a, gtext, t))
print('%d instructions: %d agree with teakra on validity and length, %d differ' % (len(L), same, bad))
sys.exit(1 if bad else 0)
