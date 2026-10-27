#!/usr/bin/env python3
"""Compare the module's decode with teakra's disassembler: validity, length and a text digest.
usage: decode_cmp.py <teakra.out> <ghidra.out> [--show N]"""
import sys, re, collections
tfile, gfile = sys.argv[1], sys.argv[2]
show = int(sys.argv[sys.argv.index('--show') + 1]) if '--show' in sys.argv else 4
T = {}
for l in open(tfile):
    h, t = l.rstrip('\n').split('\t', 1)
    f = h.split(); T[int(f[0], 16)] = (int(f[2]), t)
G = {}
for l in open(gfile):
    h, n, t = l.rstrip('\n').split(' ', 2); G[int(h[2:4] + h[0:2], 16)] = (int(n) // 2, t)
def tnorm(t):
    t = re.sub(r'\[ERROR\]3([6-9])', lambda m: 'ext%d' % (int(m.group(1)) - 6), t)
    return t
def tvalid(t):
    return '[ERROR]' not in tnorm(t)
c = collections.Counter(); ex = collections.defaultdict(list)
for op in range(65536):
    nexp, tt = T[op]
    tv = tvalid(tt)
    gl, gt = G[op]
    gv = gt != 'BAD'
    if tv and gv:
        k = 'both-valid, same length' if gl == 1 + nexp else 'both-valid, LENGTH DIFFERS'
    elif tv:
        k = 'teakra-only'
    elif gv:
        k = 'module-only'
    else:
        k = 'both-invalid'
    c[k] += 1
    if len(ex[k]) < show: ex[k].append('%04x  %s | %s' % (op, ' '.join(tnorm(tt).split()), gt))
for k, v in sorted(c.items()):
    print('%-28s %6d' % (k, v))
    if k not in ('both-invalid', 'both-valid, same length') or '--all' in sys.argv:
        for e in ex[k]: print('      ', e)
badc = sum(v for k, v in c.items() if k in ('teakra-only', 'module-only', 'both-valid, LENGTH DIFFERS'))
print('decode: %d of %d words differ in validity or length' % (badc, 65536))
sys.exit(1 if badc else 0)
