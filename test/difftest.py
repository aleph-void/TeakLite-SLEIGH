#!/usr/bin/env python3
"""Single-step differential test: Ghidra's emulator running the module's p-code vs teakra (MIT, black box).
usage: difftest.py <teakra-step> <teakra-dis> <ghidra-install> <workdir> [--ops FILE|all] [--per-op N] [--seed S] [--lang ID]
"""
import sys, os, random, subprocess, collections, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import teaksim as T

ap = argparse.ArgumentParser()
ap.add_argument('step'); ap.add_argument('dis'); ap.add_argument('ghidra'); ap.add_argument('work')
ap.add_argument('--ops', default='all'); ap.add_argument('--per-op', type=int, default=2)
ap.add_argument('--seed', type=int, default=1); ap.add_argument('--lang', default='teak:LE:16:default')
ap.add_argument('--show', type=int, default=3)
ap.add_argument('--skip', default='')
ap.add_argument('--fam', default='')
ap.add_argument('--reuse', action='store_true')
ap.add_argument('--amod', action='store_true')
ap.add_argument('--brev', action='store_true')
ap.add_argument('--self-check', action='store_true')
ap.add_argument('--skip-fam', default='')
ap.add_argument('--limit', type=int, default=0)
a = ap.parse_args()
if (a.amod or a.brev) and a.lang == 'teak:LE:16:default': a.lang = 'teak:LE:16:modulo'
os.makedirs(a.work, exist_ok=True)
HERE = os.path.dirname(os.path.abspath(__file__))
rng = random.Random(a.seed)
ops = list(range(65536)) if a.ops == 'all' else [int(x, 16) for x in open(a.ops).read().split()]
ex_vals = [0x1234, 0x0a40, 0x8005, 0x03c2]

# disassemble with teakra for grouping
inp = ''.join('%x %x\n' % (o, 0x1234) for o in ops)
dis = {}
for l in subprocess.run([a.dis], input=inp, capture_output=True, text=True).stdout.splitlines():
    h, t = l.split('\t', 1); dis[int(h[:4], 16)] = t
if a.skip_fam:
    sf = set(a.skip_fam.split(','))
    ops = [o for o in ops if not (dis[o].split() and dis[o].split()[0] in sf)]
if a.fam:
    fams = set(a.fam.split(','))
    ops = [o for o in ops if dis[o].split() and dis[o].split()[0] in fams]
    if a.limit: ops = ops[::max(1, len(ops)//a.limit)]
print('%d opcodes' % len(ops))
cases = []
for o in ops:
    for k in range(a.per_op):
        st = T.rnd_state(rng, pc=0x4000 + 4 * (len(cases) % 0x6000), amod=a.amod or a.brev, brev=a.brev)
        ex = rng.choice(ex_vals) if k else 0x1234
        # keep absolute-address expansions inside the data window
        if k == 0: ex = 0x1000 + rng.randrange(0x400)
        cases.append((o, ex, st))
with open(os.path.join(a.work, 'teakra.in'), 'w') as f:
    for o, ex, st in cases:
        f.write('%x %x ' % (o, ex) + ' '.join('%s=%x' % (k, v) for k, v in st.items()) + '\n')
with open(os.path.join(a.work, 'ghidra.in'), 'w') as f:
    for o, ex, st in cases:
        g = T.to_ghidra(st)
        f.write('%x %x pc=%x ' % (o, ex, st['pc']) + ' '.join('%s=%x' % (k, v) for k, v in g.items()) + '\n')
with open(os.path.join(a.work, 'watch.txt'), 'w') as f:
    f.write('pc\n' + '\n'.join(T.OUT_REGS) + '\n')
with open(os.path.join(a.work, 'zero.txt'), 'w') as f:
    f.write('\n'.join(T.ZERO_REGS) + '\n')
if a.reuse and os.path.exists(os.path.join(a.work, 'ghidra.out')):
    out_t = open(os.path.join(a.work, 'teakra.out')).read().splitlines()
else:
    out_t = subprocess.run([a.step], stdin=open(os.path.join(a.work, 'teakra.in')), capture_output=True, text=True).stdout.splitlines()
    open(os.path.join(a.work, 'teakra.out'), 'w').write('\n'.join(out_t) + '\n')
    env = dict(os.environ, GHIDRA_INSTALL_DIR=a.ghidra, TMPDIR='/tmp')
    subprocess.run(['bash', os.path.join(HERE, 'run-step.sh'), a.lang, os.path.join(a.work, 'ghidra.in'),
                    os.path.join(a.work, 'ghidra.out'), os.path.join(a.work, 'watch.txt'), os.path.join(a.work, 'zero.txt')], check=True, env=env)
out_g = open(os.path.join(a.work, 'ghidra.out')).read().splitlines()
assert len(out_t) == len(out_g) == len(cases), (len(out_t), len(out_g), len(cases))

skip = set(a.skip.split(',')) if a.skip else set()
stats = collections.Counter(); bad = collections.defaultdict(list)
for (o, ex, st), lt, lg in zip(cases, out_t, out_g):
    t = T.parse_line(lt); g = T.parse_line(lg)
    if 'CRASH' in t['flags'] or 'EXC' in t['flags']:
        stats['teakra-undefined'] += 1; continue
    if 'ERR' in g['flags']:
        stats['ghidra-error'] += 1
        bad[dis[o]].append((o, ex, 'GHIDRA ' + lg.split()[2], ''))
        continue
    exp = T.to_ghidra(t); diffs = []
    if a.self_check and stats['ok'] + stats['diff'] == 5: exp['a0'] ^= 1     # deliberately wrong expectation
    for r in T.OUT_REGS:
        if r in skip: continue
        if exp[r] != g.get(r): diffs.append('%s: teakra=%x ghidra=%x' % (r, exp[r], g.get(r)))
    tpc = t['pc']
    if tpc != g['pc']: diffs.append('pc: teakra=%x ghidra=%x' % (tpc, g['pc']))
    if t['pmem'] != g['pmem']: diffs.append('pmem: teakra=%s ghidra=%s' % (t['pmem'], g['pmem']))
    if t['mem'] != g['mem']: diffs.append('mem: teakra=%s ghidra=%s' % ({hex(k): hex(v) for k, v in t['mem'].items()}, {hex(k): hex(v) for k, v in g['mem'].items()}))
    if diffs:
        stats['diff'] += 1; bad[dis[o]].append((o, ex, '; '.join(diffs), '')) 
    else:
        stats['ok'] += 1
print(dict(stats))
if a.self_check:
    print('self-check: the deliberately wrong expectation was %s' % ('DETECTED' if stats['diff'] else 'NOT detected'))
    sys.exit(0 if stats['diff'] == 1 else 1)
rc = 1 if stats['diff'] or stats['ghidra-error'] else 0
byfam = collections.defaultdict(lambda: [0, []])
for d, lst in bad.items():
    import re
    fam = re.sub(r'0x[0-9a-f]+(u8)?', 'N', ' '.join(d.split()))
    fam = re.sub(r'\b(?:a|b)[01][lhe]?\b', 'ACC', fam)
    fam = re.sub(r'\br[0-7]\b', 'RN', fam)
    fam = re.sub(r'\[ERROR\]3[6-9]', 'ext', fam)
    byfam[fam][0] += len(lst); byfam[fam][1].append((d, lst))

for fam, (n, lst) in sorted(byfam.items(), key=lambda x: -x[1][0]):
    print('== %s: %d failures' % (fam, n))
    shown = 0
    for d, l in lst:
        for o, ex, msg, _ in l[:1]:
            if shown < a.show:
                print('   %04x %04x  %s\n      %s' % (o, ex, ' '.join(d.split()), msg[:400])); shown += 1
sys.exit(rc)
