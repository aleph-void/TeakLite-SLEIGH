"""State mapping and helpers for the Teak differential tests (teakra <-> Ghidra emulator)."""
import random, subprocess, os

# canonical state = teakra field names -> int
ACC = ['a0', 'a1', 'b0', 'b1']
FLAG_MAP = {'fz': 'Z', 'fm': 'M', 'fn': 'N', 'fv': 'V', 'fe': 'E', 'fc0': 'C', 'fc1': 'C1', 'flm': 'LM', 'fvl': 'VL',
            'fr': 'R', 'sat': 'SAT', 'sata': 'SATA', 's': 'S', 'hwm': 'HWM', 'ps0': 'PS0', 'ps1': 'PS1',
            'pe0': 'P0E', 'pe1': 'P1E', 'page': 'PAGE', 'stp16': 'STP16', 'cmd': 'CMD', 'epi': 'EPI', 'epj': 'EPJ',
            'ie': 'IE', 'cpc': 'CPC', 'prpage': 'prpage'}
DIRECT = ['sp', 'sv', 'mixp', 'repc', 'stepi0', 'stepj0', 'vtr0', 'vtr1'] + ['r%d' % i for i in range(8)] + ['x0', 'x1', 'y0', 'y1', 'p0', 'p1']
OUT_REGS = ['p0h'] + ACC + DIRECT + list(FLAG_MAP.values()) + ['cfgi', 'cfgj', 'mod2', 'ar0', 'ar1', 'arp0', 'arp1', 'arp2', 'arp3']

ZERO_REGS = ['SH_%s' % n for n in 'LM VL E C C1 V N M Z R'.split()] + ['SW_%s' % n for n in 'PCMHI SAT SATA HWM S PS0 PS1 PAGE STP16 CMD IM0 IM1 IM2 IMV EPI EPJ'.split()] + ['ext0', 'ext1', 'ext2', 'ext3', 'r0b', 'r1b', 'r4b', 'r7b', 'cfgib', 'cfgjb', 'stepi0b', 'stepj0b', 'ar0b', 'ar1b', 'arp0b', 'arp1b', 'arp2b', 'arp3b', 'mod2s', 'repcs', 'IU0', 'IU1', 'IP0', 'IP1', 'IP2', 'IPV', 'OU0', 'OU1', 'OU2', 'OU3', 'OU4', 'IM0', 'IM1', 'IM2', 'IMV', 'IC0', 'IC1', 'IC2',
             'NIMC', 'PCMHI', 'BCN', 'LP', 'REP', 'wb', 'wb2', 'a1s', 'b1s', 'r6', 'mixp', 'lc'] + \
            ['bkstart%d' % i for i in range(4)] + ['bkend%d' % i for i in range(4)] + ['bklc%d' % i for i in range(4)]


def pack_ar(st, i):
    # ar<i>: arstep[2i+1]:0-2 aroffset[2i+1]:3-4 arstep[2i]:5-7 aroffset[2i]:8-9 arrn[2i+1]:10-12 arrn[2i]:13-15
    return (st['arstep%d' % (2*i+1)] | st['aroffset%d' % (2*i+1)] << 3 | st['arstep%d' % (2*i)] << 5 |
            st['aroffset%d' % (2*i)] << 8 | st['arrn%d' % (2*i+1)] << 10 | st['arrn%d' % (2*i)] << 13)

def pack_arp(st, i):
    return (st['arpstepi%d' % i] | st['arpoffseti%d' % i] << 3 | st['arpstepj%d' % i] << 5 |
            st['arpoffsetj%d' % i] << 8 | st['arprni%d' % i] << 10 | st['arprnj%d' % i] << 13)

def to_ghidra(st):
    g = {}
    for a in ACC:
        g[a] = st[a] & 0xFFFFFFFFFF
    for r in DIRECT:
        g[r] = st[r]
    for k, v in FLAG_MAP.items():
        g[v] = st[k]
    g['CCNTA'] = 1; g['CREP'] = 1
    g['p0h'] = st.get('p0h_cbs', 0)
    g['cfgi'] = st['stepi'] | st['modi'] << 7
    g['cfgj'] = st['stepj'] | st['modj'] << 7
    g['mod2'] = sum(st['m%d' % i] << i | st['br%d' % i] << (8+i) for i in range(8))
    g['ar0'] = pack_ar(st, 0); g['ar1'] = pack_ar(st, 1)
    for i in range(4):
        g['arp%d' % i] = pack_arp(st, i)
    return g

def from_teakra(st):
    """teakra output (dict of fields) -> dict in module terms."""
    return to_ghidra(st)

def parse_line(line):
    f = line.split()
    d = {'op': int(f[0], 16), 'ex': int(f[1], 16), 'mem': {}, 'pmem': {}, 'flags': []}
    for t in f[2:]:
        if '=' not in t:
            d['flags'].append(t); continue
        k, v = t.split('=', 1)
        if k.startswith('pmem'):
            d['pmem'][int(k[4:], 16)] = int(v, 16)
        elif k.startswith('mem'):
            d['mem'][int(k[3:], 16)] = int(v, 16)
        elif k == 'ERR':
            d['flags'].append('ERR')
        else:
            d[k] = int(v, 16)
    return d

def brev16(v):
    return int('{:016b}'.format(v)[::-1], 2)


def rnd_state(rng, pc=0x1000, amod=False, brev=False):
    st = {}
    def acc():
        v = rng.getrandbits(40)
        if rng.random() < 0.5:
            v = (v & 0xFFFF) | (rng.choice([0, 0xFFFFFF]) << 16 & 0xFFFFFFFFFF)  # near-zero / near -1 mixes
        return v & 0xFFFFFFFFFF
    for a in ACC: st[a] = acc()
    st['a1s'] = 0; st['b1s'] = 0
    for i in range(8): st['r%d' % i] = rng.randrange(0x400, 0x2c00)
    for n in ['x0', 'x1', 'y0', 'y1', 'sv', 'mixp', 'repc', 'stepi0', 'stepj0', 'vtr0', 'vtr1', 'p0h_cbs']: st[n] = rng.getrandbits(16)
    st['p0'] = rng.getrandbits(32); st['p1'] = rng.getrandbits(32)
    st['pe0'] = rng.getrandbits(1); st['pe1'] = rng.getrandbits(1)
    st['ps0'] = rng.randrange(4); st['ps1'] = rng.randrange(4)
    st['sp'] = rng.randrange(0x800, 0x2000)
    st['page'] = rng.randrange(4, 0x10)
    for n in ['fz', 'fm', 'fn', 'fv', 'fe', 'fc0', 'fc1', 'flm', 'fvl', 'fr', 'sat', 'sata', 's', 'stp16', 'cmd', 'epi', 'epj']:
        st[n] = rng.getrandbits(1)
    st['hwm'] = rng.randrange(4)
    st['stepi'] = rng.getrandbits(7); st['stepj'] = rng.getrandbits(7)
    st['modi'] = rng.getrandbits(9); st['modj'] = rng.getrandbits(9)
    for i in range(8):
        st['m%d' % i] = rng.getrandbits(1) if amod else 0
        st['br%d' % i] = 0
        if brev and rng.getrandbits(1):
            st['br%d' % i] = 1; st['m%d' % i] = 0
            st['r%d' % i] = brev16(rng.randrange(0x400, 0x2c00))
    if not amod:
        st['cmd'] = 1; st['epi'] = 0; st['epj'] = 0
    for i in range(4):
        st['arstep%d' % i] = rng.randrange(8); st['aroffset%d' % i] = rng.randrange(4); st['arrn%d' % i] = rng.randrange(8)
        st['arpstepi%d' % i] = rng.randrange(8); st['arpstepj%d' % i] = rng.randrange(8)
        st['arpoffseti%d' % i] = rng.randrange(4); st['arpoffsetj%d' % i] = rng.randrange(4)
        st['arprni%d' % i] = rng.randrange(4); st['arprnj%d' % i] = rng.randrange(4)
    st['ie'] = 0; st['cpc'] = rng.getrandbits(1)
    st['prpage'] = 0; st['pc'] = pc
    return st
