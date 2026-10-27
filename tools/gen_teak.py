#!/usr/bin/env python3
"""Generates data/languages/teak_{tokens,tables,insts}.sinc for the Teak / TeakLite II DSP.

The instruction encodings come from tools/teak_insts.json (extracted from teakra's decoder table, see
extract_teakra_table.py); the semantics are written in teak_sem.py.  usage: gen_teak.py <outdir>"""
import json, os, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from teak_lib import *
import teak_sem

HERE = os.path.dirname(os.path.abspath(__file__))
INSTS = json.load(open(os.path.join(HERE, 'teak_insts.json')))


class Op:
    """One operand of an instruction after the grouping of address register + step pairs."""
    def __init__(self, typ, kind=None, pos=None, val=None):
        self.typ = typ          # 'At', 'AtNamed', 'Const', 'Cn', 'Unused', or a group name
        self.kind, self.pos, self.val = kind, pos, val
        self.members = []       # for groups
        self.enumname = None    # set when an enum kind is expanded

    @property
    def fld(self):
        return '%s_%d' % (self.kind, self.pos)

    @property
    def expansion(self):
        return self.pos == 16


def group_ops(raw):
    ops = []
    i = 0
    while i < len(raw):
        r = raw[i]
        if r[0] in ('At', 'AtNamed'):
            o = Op(r[0], r[1], r[2])
        elif r[0] == 'Const':
            o = Op('Const', r[1], None, int(r[2]))
        elif r[0] == 'Unused':
            o = Op('Unused', None, r[1])
        else:
            o = Op('Cn', None, None, r[1])
        ops.append(o)
        i += 1
    # group Rn+step, ArRn+ArStep, ArpRn+2*ArpStep
    out = []
    i = 0
    while i < len(ops):
        o = ops[i]
        n = ops[i + 1] if i + 1 < len(ops) else None
        n2 = ops[i + 2] if i + 2 < len(ops) else None
        if o.typ == 'At' and o.kind in ('Rn', 'R45', 'R0123') and n and n.kind == 'StepZIDS':
            g = Op('RnStep'); g.members = [o, n]; out.append(g); i += 2; continue
        if o.typ == 'At' and o.kind in ('ArRn1', 'ArRn2') and n and n.kind in ('ArStep1', 'ArStep1Alt', 'ArStep2'):
            g = Op('ArMem'); g.members = [o, n]; out.append(g); i += 2; continue
        if o.typ == 'At' and o.kind in ('ArpRn1', 'ArpRn2') and n and n2 and n.kind.startswith('ArpStep'):
            g = Op('ArpMem'); g.members = [o, n, n2]; out.append(g); i += 3; continue
        out.append(o); i += 1
    return out


class Gen:
    def __init__(self):
        self.fixed_fields = {}   # name -> (lo, hi)
        self.op_fields = {}      # name -> (token, lo, hi, signed, attach)
        self.tables = collections.OrderedDict()   # table text keyed by name (emitted once)
        self.table_users = {}
        self.cons = []
        self.n = 0

    # ---- field helpers ----
    def fixed(self, lo, hi):
        name = 'f_%d_%d' % (lo, hi)
        self.fixed_fields[name] = (lo, hi)
        return name

    def field(self, kind, pos, alias=None, signed=None, attach=None):
        """Operand field over the bits of an operand; returns its name."""
        name = '%s_%d' % (alias or kind, pos)
        w = BITS[kind]
        tok = 'teakop'
        lo = 0 if pos == 16 else pos
        sg = (kind in SIGNED) if signed is None else signed
        self.op_fields[name] = (tok, lo, lo + w - 1, sg, attach, kind.startswith('Ar'))
        return name

    def fld_extra(self, kind, pos, tag, lo_off=0, width=None, attach=None):
        """A second field over (part of) the bits of an operand."""
        name = '%s%s_%d' % (kind, tag, pos)
        w = width or BITS[kind]
        self.op_fields[name] = ('teakop', pos + lo_off, pos + lo_off + w - 1, False, attach, False)
        return name


G = Gen()


def mask_of(ops):
    m = 0
    for o in ops:
        if o.typ in ('At', 'AtNamed'):
            if o.pos != 16:
                m |= ((1 << BITS[o.kind]) - 1) << o.pos
        elif o.typ == 'Unused':
            m |= 1 << o.pos
        elif o.members:
            for x in o.members:
                m |= ((1 << BITS[x.kind]) - 1) << x.pos
    return m


def fixed_pattern(opcode, mask):
    """f_lo_hi=value for every run of fixed bits."""
    fixed = (~mask) & 0xFFFF
    parts = []
    i = 0
    while i < 16:
        if fixed >> i & 1:
            j = i
            while j + 1 < 16 and fixed >> (j + 1) & 1:
                j += 1
            val = (opcode >> i) & ((1 << (j - i + 1)) - 1)
            parts.append('%s=0x%x' % (G.fixed(i, j), val))
            i = j + 1
        else:
            i += 1
    return parts


# ------------------------------------------------------------------------------------------------
# views of the flag / mode bytes as the 16 bit control registers
# ------------------------------------------------------------------------------------------------
# (byte register, position, width, kind) kind: '' normal, 'ro' read only, 'const:<v>', 'lp', 'dbl' (flm/vlm), 'acce:<acc>'
VIEWS = {
    'stt0': [('LM', 0, 1), ('VL', 1, 1), ('E', 2, 1), ('C', 3, 1), ('V', 4, 1), ('N', 5, 1), ('M', 6, 1), ('Z', 7, 1), ('C1', 11, 1)],
    'stt1': [('R', 4, 1), ('IU0', 10, 1, 'ro'), ('IU1', 11, 1, 'ro'), ('P0E', 14, 1), ('P1E', 15, 1)],
    'stt2': [('IP0', 0, 1, 'ro'), ('IP1', 1, 1, 'ro'), ('IP2', 2, 1, 'ro'), ('IPV', 3, 1, 'ro'), ('PCMHI', 6, 2),
             ('BCN', 12, 3, 'ro'), ('LP', 15, 1, 'lp')],
    'mod0': [('SAT', 0, 1), ('SATA', 1, 1), (None, 2, 3, 'const:1'), ('HWM', 5, 2), ('S', 7, 1), ('OU0', 8, 1), ('OU1', 9, 1),
             ('PS0', 10, 2), ('PS1', 13, 2)],
    'mod1': [('PAGE', 0, 8), ('STP16', 12, 1), ('CMD', 13, 1), ('EPI', 14, 1), ('EPJ', 15, 1)],
    'mod3': [('NIMC', 0, 1), ('IC0', 1, 1), ('IC1', 2, 1), ('IC2', 3, 1), ('OU2', 4, 1), ('OU3', 5, 1), ('OU4', 6, 1), ('IE', 7, 1),
             ('IM0', 8, 1), ('IM1', 9, 1), ('IM2', 10, 1), ('IMV', 11, 1), ('CCNTA', 13, 1), ('CPC', 14, 1), ('CREP', 15, 1)],
    'st0': [('SAT', 0, 1), ('IE', 1, 1), ('IM0', 2, 1), ('IM1', 3, 1), ('R', 4, 1), ('LM', 5, 1, 'dbl'), ('E', 6, 1), ('C', 7, 1),
            ('V', 8, 1), ('N', 9, 1), ('M', 10, 1), ('Z', 11, 1), ('a0', 12, 4, 'acce')],
    'st1': [('PAGE', 0, 8), ('PS0', 10, 2), ('a1', 12, 4, 'acce')],
    'st2': [('mod2', 0, 6, 'm'), ('IM2', 6, 1), ('S', 7, 1), ('OU0', 8, 1), ('OU1', 9, 1), ('IU0', 10, 1, 'ro'), ('IU1', 11, 1, 'ro'),
            ('IP2', 13, 1, 'ro'), ('IP0', 14, 1, 'ro'), ('IP1', 15, 1, 'ro')],
    'icr': [('NIMC', 0, 1), ('IC0', 1, 1), ('IC1', 2, 1), ('IC2', 3, 1), ('LP', 4, 1, 'lp'), ('BCN', 5, 3, 'ro')],
}
# registers that really are 16 bit registers in the module (nothing to compose)
REAL16 = {'mod2', 'ar0', 'ar1', 'arp0', 'arp1', 'arp2', 'arp3', 'cfgi', 'cfgj'}
ARP_MASK = 0x6fff


def compose(view, out):
    """statements that build `out` (2 bytes) from the byte registers"""
    parts = []
    for s in VIEWS[view]:
        reg, pos, w = s[0], s[1], s[2]
        kind = s[3] if len(s) > 3 else ''
        if kind.startswith('const:'):
            parts.append('(%d << %d)' % (int(kind[6:]), pos))
        elif kind == 'dbl':
            parts.append('(zext(LM | VL) << %d)' % pos)
        elif kind == 'acce':
            parts.append('(zext(%s[32,4]) << %d)' % (reg, pos))
        elif kind == 'm':
            parts.append('(mod2 & 0x%x)' % ((1 << w) - 1))
        else:
            parts.append('(zext(%s) << %d)' % (reg, pos) if w > 0 else '')
    return '    %s = %s;\n' % (out, ' | '.join(parts))


def decompose(view, val):
    s = ''
    for it in VIEWS[view]:
        reg, pos, w = it[0], it[1], it[2]
        kind = it[3] if len(it) > 3 else ''
        if kind in ('ro',) or kind.startswith('const'):
            continue
        if kind == 'lp':
            s += '    if (%s[%d,1] == 0) goto <lp%d>;\n    LP = 0;\n    BCN = 0;\n  <lp%d>\n' % (val, pos, pos, pos)
        elif kind == 'dbl':
            s += '    LM = %s[%d,1];\n    VL = %s[%d,1];\n' % (val, pos, val, pos)
        elif kind == 'acce':
            s += '    local e%s:1 = %s[%d,4];\n    %s[32,8] = (e%s << 4) s>> 4;\n' % (reg, val, pos, reg, reg)
        elif kind == 'm':
            s += '    mod2 = (mod2 & ~0x%x) | (%s & 0x%x);\n' % ((1 << w) - 1, val, (1 << w) - 1)
        else:
            s += '    %s = %s[%d,%d];\n' % (reg, val, pos, w)
    return s


def view_macros():
    t = ''
    for v in VIEWS:
        t += 'macro Compose_%s(out)\n{\n%s}\n\n' % (v, compose(v, 'out'))
        t += 'macro Decompose_%s(val)\n{\n%s}\n\n' % (v, decompose(v, 'val'))
    return t


# ------------------------------------------------------------------------------------------------
# operand tables
# ------------------------------------------------------------------------------------------------
def add_table(name, text):
    G.tables.setdefault(name, text)


ACCS = {'a0': 'a0', 'a1': 'a1', 'b0': 'b0', 'b1': 'b1'}


def reg_read_body(idx, sat):
    """statements + export for Register index idx read as 16 bit bus value"""
    names = ATTACH['Register']
    n = names[idx]
    if idx < 8 or n in ('sp', 'sv', 'cfgi', 'cfgj') or n.startswith('ext'):
        return '    export %s;\n' % n
    if n in ('st0', 'st1', 'st2'):
        return '    local t:2 = 0;\n    Compose_%s(t);\n    export t;\n' % n
    if n == 'p0h':
        return '    local v:8 = 0;\n    P40_0(v);\n    local vw:8 = v >> 16;\n    local t:2 = vw:2;\n    export t;\n'
    if n == 'pc16':
        return '    local t4:4 = inst_next;\n    t4 = t4 >> 1;\n    local t:2 = t4:2;\n    export t;\n'
    if n == 'lc':
        return ('    local i:4 = 0;\n    if (LP == 0) goto <z>;\n    i = zext(BCN) - 1;\n  <z>\n'
                '    local ptr:4 = &bklc0 + (i * 2);\n    local t:2 = *[register]:2 ptr;\n    export t;\n')
    # accumulator parts
    acc = n[:2]
    part = n[2:]
    if idx in (24, 25):
        acc, part = ('a0' if idx == 24 else 'a1'), ''
    if part == '':          # a0 / a1: low 16 bits, never saturated
        return '    local t:2 = %sl;\n    export t;\n' % acc
    if not sat:
        return '    export %s;\n' % n
    sh = '' if part == 'l' else ' >> 16'
    return '    local v:8 = 0;\n    GetSatAcc(v, %s);\n    local vw:8 = v%s;\n    local t:2 = vw:2;\n    export t;\n' % (acc, sh)


def reg_write_body(idx):
    names = ATTACH['Register']
    n = names[idx]
    if idx < 8 or n in ('sp', 'sv', 'cfgi', 'cfgj') or n.startswith('ext'):
        return '    %s = wb;\n' % n
    if n in ('st0', 'st1', 'st2'):
        return '    Decompose_%s(wb);\n' % n
    if n == 'p0h':
        return '    P0E = (wb > 0x7fff);\n    p0 = (p0 & 0xffff) | (zext(wb) << 16);\n'
    if n == 'pc16':
        return ''
    if n == 'lc':
        return ('    local i:4 = 0;\n    if (LP == 0) goto <z>;\n    i = zext(BCN) - 1;\n  <z>\n'
                '    local ptr:4 = &bklc0 + (i * 2);\n    *[register]:2 ptr = wb;\n')
    acc = n[:2]
    part = n[2:]
    if idx in (24, 25):
        acc, part = ('a0' if idx == 24 else 'a1'), ''
    if part == '':
        return '    local v:8 = sext(wb);\n    SatAndSetAccAndFlag(%s, v);\n' % acc
    if part == 'l':
        return '    local v:8 = zext(wb);\n    SatAndSetAccAndFlag(%s, v);\n' % acc
    return '    local w4:4 = zext(wb);\n    w4 = w4 << 16;\n    local v:8 = sext(w4);\n    SatAndSetAccAndFlag(%s, v);\n' % acc


def gen_register_tables(pos):
    f = G.field('Register', pos, attach=ATTACH['Register'])
    for tag, sat in (('RdR', False), ('RdRS', True)):
        text = ''
        for i in range(32):
            if pos == 5 and i in (24, 25):
                continue    # excluded at bit 5 (mov Register,[Rn] is overridden by mov_r6)
            text += '%s_%d: is %s=%d\n{\n%s}\n' % (tag, pos, f, i, reg_read_body(i, sat))
        add_table('%s_%d' % (tag, pos), text)
    text = ''
    for i in range(32):
        text += 'WrR_%d: is %s=%d\n{\n%s}\n' % (pos, f, i, reg_write_body(i))
    add_table('WrR_%d' % pos, text)
    return f


# SttMod / ArArp / ArArpSttMod: names by field value
SM_NAMES = ['stt0', 'stt1', 'stt2', None, 'mod0', 'mod1', 'mod2', 'mod3']
AA_NAMES = ['ar0', 'ar1', 'arp0', 'arp1', 'arp2', 'arp3', None, None]
AASM_NAMES = AA_NAMES + SM_NAMES


def ctl_read_body(n):
    if n in VIEWS:
        return '    local t:2 = 0;\n    Compose_%s(t);\n    export t;\n' % n
    return '    export %s;\n' % n


def ctl_write_body(n):
    if n in VIEWS:
        return '    Decompose_%s(wb);\n' % n
    if n.startswith('arp'):
        return '    %s = wb & 0x%x;\n' % (n, ARP_MASK)
    return '    %s = wb;\n' % n


def gen_ctl_tables(kind, pos, names):
    f = G.field(kind, pos, attach=[n if n else '_' for n in names])
    rd = wr = ''
    for i, n in enumerate(names):
        if n is None:
            continue
        rd += 'RdC%s_%d: is %s=%d\n{\n%s}\n' % (kind, pos, f, i, ctl_read_body(n))
        wr += 'WrC%s_%d: is %s=%d\n{\n%s}\n' % (kind, pos, f, i, ctl_write_body(n))
    add_table('RdC%s_%d' % (kind, pos), rd)
    add_table('WrC%s_%d' % (kind, pos), wr)
    return f


def gen_cond_table(pos):
    f = G.field('Cond', pos)
    conds = ['1', 'Z != 0', 'Z == 0', '(M == 0) && (Z == 0)', 'M == 0', 'M != 0', '(M != 0) || (Z != 0)', 'N == 0',
             'C != 0', 'V != 0', 'E != 0', '(LM != 0) || (VL != 0)', 'R == 0', 'IU0 == 0', 'IU0 != 0', 'IU1 != 0']
    text = ''
    for i, (nm, ex) in enumerate(zip(COND, conds)):
        if i == 0:
            continue        # the unconditional form has its own constructors
        text += 'CondT_%d: "%s" is %s=%d\n{\n    local c:1 = (%s);\n    export c;\n}\n' % (pos, nm, f, i, ex)
        text = text.replace('local c:1 = (1);', 'local c:1 = 1;')
    add_table('CondT_%d' % pos, text)
    return f


def gen_mem_table(kind, pos):
    fi = G.field(kind, pos, alias=kind + 'I')
    nm = '%s_%d' % (kind, pos)
    if kind == 'MemImm8':
        t = '%s: "[PAGE:"^%s^"]" is %s\n{\n    local a:2 = (zext(PAGE) << 8) + %s;\n    export *[DATA]:2 a;\n}\n' % (nm, fi, fi, fi)
        t = t.replace('+ %s;' % fi, '+ zext(%s:1);' % fi) if False else t
    elif kind == 'MemImm16':
        t = '%s: "["^%s^"]" is %s\n{\n    local a:2 = %s;\n    export *[DATA]:2 a;\n}\n' % (nm, fi, fi, fi)
    elif kind == 'MemR7Imm16':
        t = '%s: "[r7+"^%s^"]" is %s\n{\n    local a:2 = r7 + %s;\n    export *[DATA]:2 a;\n}\n' % (nm, fi, fi, fi)
    else:
        t = '%s: "[r7+"^%s^"]" is %s\n{\n    local o:2 = %s;\n    local a:2 = r7 + o;\n    export *[DATA]:2 a;\n}\n' % (nm, fi, fi, fi)
    add_table(nm, t)
    return nm


def gen_stepstr(pos):
    nm = 'StepStr_%d' % pos
    fs = G.field('StepZIDS', pos, alias='StepN')
    text = ''.join('%s: "%s" is %s=%d\n{\n}\n' % (nm, STEPS[i], fs, i) for i in range(4))
    add_table(nm, text)
    return nm, fs


def gen_rnstep_table(o, dmod, addr=False):
    r, s = o.members
    fr = G.field(r.kind, r.pos, attach=ATTACH[r.kind])
    frn = G.field(r.kind, r.pos, alias=r.kind + 'N')
    fs = G.field('StepZIDS', s.pos)
    ss, fsn = gen_stepstr(s.pos)
    nm = 'Rn%s_%s_%d_%d%s' % ('A' if addr else 'S', r.kind, r.pos, s.pos, 'd' if dmod else '')
    exp = 'export a;' if addr else 'export *[DATA]:2 a;'
    text = ''
    rnames = ATTACH[r.kind]
    base = 4 if r.kind == 'R45' else 0
    for ri, rn in enumerate(rnames):
        unit = int(rn[1:])
        for st in range(4):
            lit = '[%s%s]' % (rn, STEPS[st])
            if st == 0:
                body = '    local a:2 = %s;\n' % rn
            elif st == 1:
                body = '    local a:2 = %s;\n    %s = %s + 1;\n' % (rn, rn, rn)
            elif st == 2:
                body = '    local a:2 = %s;\n    %s = %s - 1;\n' % (rn, rn, rn)
            else:
                cfg = 'cfgi' if unit < 4 else 'cfgj'
                body = '    local a:2 = %s;\n    %s = %s + (((%s & 0x7f) << 9) s>> 9);\n' % (rn, rn, rn, cfg)
            text += '%s: "%s" is %s=%d & %s=%d & AMOD=0\n{\n%s    %s\n}\n' % (nm, lit, fr, ri, fs, st, body, exp)
    body = ('    local a:2 = 0;\n    local u:1 = %d + %s;\n    local st:1 = %s;\n    local dm:1 = %d;\n    RnAddrFull(a, u, st, dm);\n'
            '    %s\n') % (base, frn, fsn, 1 if dmod else 0, exp)
    text += '%s: "["^%s^%s^"]" is %s & %s & %s & %s & AMOD=1\n{\n%s}\n' % (nm, fr, ss, fr, frn, ss, fsn, body)
    add_table(nm, text)
    return nm


def gen_rnfix_table(o, step, dmod):
    k = o.kind
    fr = G.field(k, o.pos, attach=ATTACH[k])
    frn = G.field(k, o.pos, alias=k + 'N')
    nm = 'RnF_%s_%d_%d%d' % (k, o.pos, step, dmod)
    text = ''
    for ri, rn in enumerate(ATTACH[k]):
        d = '+ 2' if step == 4 else '- 2'
        text += '%s: "%s" is %s=%d & AMOD=0\n{\n    %s = %s %s;\n}\n' % (nm, rn, fr, ri, rn, rn, d)
    text += ('%s: %s is %s & %s & AMOD=1\n{\n    local a:2 = 0;\n    local u:1 = %s;\n    local st:1 = %d;\n    local dm:1 = %d;\n'
             '    RnAddrFull(a, u, st, dm);\n}\n') % (nm, fr, fr, frn, frn, step, dmod)
    add_table(nm, text)
    return nm


def gen_r0step_table(pos):
    fs = G.field('StepZIDS', pos)
    ss, fsn = gen_stepstr(pos)
    nm = 'R0S_%d' % pos
    text = ''
    for st in range(4):
        lit = '[r0%s]' % STEPS[st]
        body = ['    local a:2 = r0;\n', '    local a:2 = r0;\n    r0 = r0 + 1;\n', '    local a:2 = r0;\n    r0 = r0 - 1;\n',
                '    local a:2 = r0;\n    r0 = r0 + (((cfgi & 0x7f) << 9) s>> 9);\n'][st]
        text += '%s: "%s" is %s=%d & AMOD=0\n{\n%s    export *[DATA]:2 a;\n}\n' % (nm, lit, fs, st, body)
    body = '    local a:2 = 0;\n    local u:1 = 0;\n    local st:1 = %s;\n    local dm:1 = 0;\n    RnAddrFull(a, u, st, dm);\n    export *[DATA]:2 a;\n' % fsn
    text += '%s: "[r0"^%s^"]" is %s & %s & AMOD=1\n{\n%s}\n' % (nm, ss, ss, fsn, body)
    add_table(nm, text)
    return nm


def gen_arm_table(o, dmod=False):
    r, s = o.members
    fr = G.field(r.kind, r.pos)
    fs = G.field(s.kind, s.pos)
    nm = 'ArM_%s_%d_%s_%d' % (r.kind, r.pos, s.kind, s.pos)
    soff = 2 if s.kind == 'ArStep1Alt' else 0
    text = ''
    for amod in (0, 1):
        body = '    local u:1 = 0;\n    local st:1 = 0;\n    local of:1 = 0;\n    local ri:1 = %s;\n    local si:1 = %s + %d;\n' % (fr, fs, soff)
        body += '    ArFields(u, st, of, ri, si);\n'
        if amod == 0:
            body += ('    local old:2 = 0;\n    RGet(old, u);\n    local s:2 = 0;\n    StepSimple(s, u, st);\n    RSet(u, old + s);\n'
                     '    local oa:2 = 0;\n    OffAddrSimple(oa, old, of);\n')
        else:
            body += '    local dm:1 = 0;\n    local old:2 = 0;\n    RnAddrFull(old, u, st, dm);\n    local oa:2 = 0;\n    OffAddrFull(oa, u, old, of, dm);\n'
        body += '    local pk:4 = zext(old) | (zext(oa) << 16);\n    export pk;\n'
        text += '%s: "[arrn"^%s^"+ars"^%s^"]" is %s & %s & AMOD=%d\n{\n%s}\n' % (nm, fr, fs, fr, fs, amod, body)
    add_table(nm, text)
    return nm


def gen_arpm_table(o, dmodi, dmodj):
    r, si, sj = o.members
    fr = G.field(r.kind, r.pos)
    fi = G.field(si.kind, si.pos)
    fj = G.field(sj.kind, sj.pos)
    nm = 'ArpM_%d_%d_%d_%d%d' % (r.pos, si.pos, sj.pos, dmodi, dmodj)
    text = ''
    for amod in (0, 1):
        body = ('    local ui:1 = 0; local uj:1 = 0; local sti:1 = 0; local stj:1 = 0; local oi:1 = 0; local oj:1 = 0;\n'
                '    local rn:1 = %s; local ai:1 = %s; local aj:1 = %s;\n    ArpFields(ui, uj, sti, stj, oi, oj, rn, ai, aj);\n' % (fr, fi, fj))
        if amod == 0:
            body += ('    local ia:2 = 0; local ja:2 = 0; local s:2 = 0;\n'
                     '    RGet(ia, ui);\n    StepSimple(s, ui, sti);\n    RSet(ui, ia + s);\n'
                     '    RGet(ja, uj);\n    StepSimple(s, uj, stj);\n    RSet(uj, ja + s);\n'
                     '    local ioa:2 = 0; local joa:2 = 0;\n    OffAddrSimple(ioa, ia, oi);\n    OffAddrSimple(joa, ja, oj);\n')
        else:
            body += ('    local ia:2 = 0; local ja:2 = 0; local ioa:2 = 0; local joa:2 = 0;\n    local di:1 = %d; local dj:1 = %d;\n'
                     '    RnAddrFull(ia, ui, sti, di);\n    RnAddrFull(ja, uj, stj, dj);\n'
                     '    OffAddrFull(ioa, ui, ia, oi, di);\n    OffAddrFull(joa, uj, ja, oj, dj);\n' % (dmodi, dmodj))
        body += '    local pk:8 = zext(ia) | (zext(ioa) << 16) | (zext(ja) << 32) | (zext(joa) << 48);\n    export pk;\n'
        text += '%s: "[arprn"^%s^"+arpsi"^%s^"+arpsj"^%s^"]" is %s & %s & %s & AMOD=%d\n{\n%s}\n' % (nm, fr, fi, fj, fr, fi, fj, amod, body)
    add_table(nm, text)
    return nm


# ------------------------------------------------------------------------------------------------
# instruction emission
# ------------------------------------------------------------------------------------------------
class Ctx:
    def __init__(self, name, ops):
        self.name, self.ops, self.k = name, ops, 0
        self.pre = []        # extra statements emitted before the body (none by default)

    def tmp(self, p='t'):
        self.k += 1
        return '%s%d' % (p, self.k)


def prep(o, c):
    """fills o.disp, o.part, o.pat, o.build for operand o"""
    o.disp, o.part, o.pat, o.build = None, 1, [], []
    k = o.kind
    if o.typ == 'Unused' or o.typ == 'Cn':
        return
    if o.typ == 'Const':
        if k in ENUM:
            return
        o.reg = ATTACH[k][o.val]
        o.disp = '"%s"' % o.reg
        return
    if o.enumname == 'always' and k == 'Cond':
        f = gen_cond_table(o.pos)
        o.disp, o.pat, o.cond = '"always"', ['%s=0' % f], None
        return
    if o.enumname is not None and k == 'Register':
        f = gen_register_tables(o.pos)
        o.disp, o.pat = '"%s"' % o.enumname, ['%s=%d' % (f, o.val)]
        o.rd, o.rds, o.wr = 'RdR_%d' % o.pos, 'RdRS_%d' % o.pos, 'WrR_%d' % o.pos
        return
    if o.enumname is not None:            # an expanded At operand
        f = G.field(k, o.pos, attach=ATTACH.get(k)) if k in BITS else None
        o.pat = ['%s=%d' % (f, o.val)]
        if k in ATTACH and k not in ENUM:
            o.reg = ATTACH[k][o.val]
            o.disp = '"%s"' % o.reg
        elif k == 'SwapType':
            o.disp = '"%s"' % o.enumname
        return
    if o.typ == 'RnStep':
        r, s = o.members
        o.dmod = getattr(o, 'dmod', False)
        nm = gen_rnstep_table(o, o.dmod, c.name in teak_sem.ADDR_NAMES)
        o.disp, o.build, o.pat = nm, [nm], [nm]
        o.unitf = G.field(r.kind, r.pos, alias=r.kind + 'N')
        return
    if o.typ == 'ArMem':
        nm = gen_arm_table(o)
        o.disp, o.build, o.pat = nm, [nm], [nm]
        return
    if o.typ == 'ArpMem':
        nm = gen_arpm_table(o, getattr(o, 'dmodi', 0), getattr(o, 'dmodj', 0))
        o.disp, o.build, o.pat = nm, [nm], [nm]
        return
    if o.typ not in ('At', 'AtNamed'):
        raise Exception('?')
    p = o.pos
    if k == 'Rn' and c.name in teak_sem.FIXSTEP:
        st, dm = teak_sem.FIXSTEP[c.name]
        nm = gen_rnfix_table(o, st, dm)
        o.disp, o.build, o.pat = nm, [nm], [nm]
        o.unitf = G.field(k, p, alias=k + 'N')
        return
    if k in ('Ax', 'Bx', 'Ab', 'Px', 'RnOld', 'Rn', 'R45', 'R0123', 'Ar', 'Arp') or k in FULL or k == 'Ablh':
        f = G.field(k, p, attach=ATTACH[k])
        o.disp, o.pat, o.reg = f, [f], f
        if k in FULL:
            o.full = G.fld_extra(k, p, 'F', attach=ATTACH[FULL[k]])
            o.pat.append(o.full)
        elif k == 'Ablh':
            o.full = G.fld_extra(k, p, 'F', lo_off=1, width=2, attach=ATTACH['Ab'][0:0] or ['b0', 'b1', 'a0', 'a1'])
            o.half = G.fld_extra(k, p, 'H', width=1)
            o.pat += [o.full, o.half]
        elif k in ('Ax', 'Bx', 'Ab'):
            o.full = f
        return
    if k == 'Register':
        f = gen_register_tables(p)
        o.disp, o.pat = f, [f] + ['%s!=%d' % (G.field(k, p, alias='RegisterC'), x) for x in getattr(o, 'exclude', ())]
        o.rd, o.rds, o.wr = 'RdR_%d' % p, 'RdRS_%d' % p, 'WrR_%d' % p
        o.num = G.field('Register', p, alias='RegisterN')
        return
    if k in ('SttMod', 'ArArp', 'ArArpSttMod'):
        names = {'SttMod': SM_NAMES, 'ArArp': AA_NAMES, 'ArArpSttMod': AASM_NAMES}[k]
        f = gen_ctl_tables(k, p, names)
        o.disp, o.pat = f, [f]
        o.rd, o.wr = 'RdC%s_%d' % (k, p), 'WrC%s_%d' % (k, p)
        return
    if k == 'StepZIDS':
        nm = gen_r0step_table(p)
        o.disp, o.build, o.pat = nm, [nm], [nm]
        return
    if k in ('ArRn1', 'ArRn2'):
        f = G.field(k, p)
        o.disp, o.pat, o.imm = f, [f], f
        return
    if k == 'Cond':
        f = gen_cond_table(p)
        o.disp, o.pat, o.build = 'CondT_%d' % p, ['CondT_%d' % p, f], ['CondT_%d' % p]
        if getattr(o, 'not_always', False):
            o.pat.append('%s!=0' % G.field('Cond', p, alias='CondC'))
        o.cond = 'CondT_%d' % p
        return
    if k in ('MemImm8', 'MemImm16', 'MemR7Imm16', 'MemR7Imm7s'):
        nm = gen_mem_table(k, p)
        o.disp, o.pat, o.build = nm, [nm], [nm]
        o.mem = nm
        o.part = 2 if p == 16 else 1
        return
    if k in ('Imm2', 'Imm4', 'Imm5', 'Imm5s', 'Imm6s', 'Imm7s', 'Imm8', 'Imm8s', 'Imm9', 'Imm16', 'BankFlags', 'CbsCond', 'RelAddr7'):
        f = G.field(k, p)
        o.disp, o.pat, o.imm = f, [f], f
        o.part = 2 if p == 16 else 1
        if k == 'RelAddr7':
            # branch target as an address
            nm = 'Rel7_%d' % p
            add_table(nm, '%s: reloc is %s [ reloc = inst_next + %s; ]\n{\n    export *[CODE]:3 reloc;\n}\n' % (nm, f, f))
            o.disp, o.pat, o.build, o.target = nm, [nm], [], nm
        return
    if k == 'Address18_2':
        return     # handled together with Address18_16
    if k == 'Address18_16':
        hi = [x for x in c.ops if x.kind == 'Address18_2'][0]
        f2 = G.field('Address18_2', hi.pos)
        f16 = G.field('Address18_16', 16)
        nm = 'BrT_%d' % hi.pos
        if c.name.startswith('bkrep'):
            nm = 'BrV_%d' % hi.pos
            add_table(nm, '%s: target is %s ; %s [ target = (%s << 16) | %s; ]\n{\n    local t:4 = target;\n    export t;\n}\n' % (nm, f2, f16, f2, f16))
        else:
            add_table(nm, '%s: target is %s ; %s [ target = (%s << 16) | %s; ]\n{\n    export *[CODE]:3 target;\n}\n' % (nm, f2, f16, f2, f16))
        o.disp, o.pat, o.target = nm, [nm], nm
        o.part = 1
        return
    if k == 'Address16':
        f = G.field(k, 16)
        o.disp, o.pat, o.imm, o.part = f, [f], f, 2
        return
    raise Exception('prep: %s' % k)


# kinds that are expanded to one constructor per value when an instruction needs a constant operand
def expansions(name, ops, opcode=0):
    """returns list of op lists with expanded enum / constant operands"""
    want = teak_sem.EXPAND.get(name, ())
    combos = [[]]
    for o in ops:
        choices = None
        if o.typ in ('At', 'AtNamed') and (o.kind in ENUM or o.kind in want or o.kind == 'Px'):
            choices = []
            vals = ENUM[o.kind] if o.kind in ENUM else ATTACH[o.kind]
            for v, nm in enumerate(vals):
                if nm is None:
                    continue
                n = Op(o.typ, o.kind, o.pos, v)
                n.enumname = nm
                choices.append(n)
        elif o.typ in ('At', 'AtNamed') and o.kind == 'Register' and (opcode, o.pos) in teak_sem.REGSPLIT:
            choices = []
            idxs = teak_sem.REGSPLIT[(opcode, o.pos)]
            for v in idxs:
                n = Op(o.typ, o.kind, o.pos, v)
                n.enumname = {24: 'a0', 25: 'a1', 11: 'p0h', 12: 'pc'}.get(v, ATTACH['Register'][v])
                choices.append(n)
            g = Op(o.typ, o.kind, o.pos)
            g.exclude = idxs
            choices.append(g)
        elif o.typ in ('At', 'AtNamed') and o.kind == 'Cond':
            a = Op(o.typ, o.kind, o.pos, 0)
            a.enumname = 'always'
            g = Op(o.typ, o.kind, o.pos)
            g.not_always = True
            choices = [a, g]
        elif o.typ == 'Const' and o.kind in ENUM:
            n = Op('Const', o.kind, None, o.val)
            n.enumname = ENUM[o.kind][o.val]
            choices = [n]
        combos = [c + [x] for c in combos for x in (choices or [o])]
    return combos


def build_constructor(inst, ops):
    name = inst['name']
    c = Ctx(name, ops)
    dm = [o.val for o in ops if o.typ == 'Cn' and o.val in ('EMod', 'DMod')]
    named = {'modr_dmod': 1, 'modr_i2_dmod': 1, 'modr_d2_dmod': 1, 'modr_edmod': (0, 1), 'modr_demod': (1, 0), 'modr_ddmod': (1, 1), 'modr_eemod': (0, 0)}
    for o in ops:
        if o.typ == 'RnStep' and named.get(name) == 1:
            o.dmod = True
        if o.typ == 'ArpMem':
            if dm:
                o.dmodi, o.dmodj = int(dm[0] == 'DMod'), int(dm[1] == 'DMod')
            elif isinstance(named.get(name), tuple):
                o.dmodi, o.dmodj = named[name]
    for o in ops:
        prep(o, c)
    body, sub_order = teak_sem.emit(c, inst, ops)
    mask = mask_of(ops)
    pat1 = fixed_pattern(inst['opcode'], mask)
    pat2 = []
    for o in ops:
        (pat2 if o.part == 2 else pat1).extend(o.pat)
    for (k, p, v) in inst['except']:
        if any(o.kind == k and o.pos == p and o.enumname for o in ops):
            continue        # an explicit value is not one of the excluded ones
        f = G.field(k, p, alias=k + 'C')
        pat1.append('%s!=%d' % (f, v))
    # mnemonic: enum value name replaces the instruction name for generic instructions
    mnem = name.rstrip('_')
    en = [o for o in ops if o.enumname is not None and o.kind in ENUM and o.kind != 'SwapType']
    if en:
        mnem = en[0].enumname
    elif name.startswith('mma'):
        mnem = name
    disp = [o.disp for o in ops if o.disp and not (o.kind == 'Address18_2')]
    if body is None:
        body = ''
        G.unimpl.add(name)
    builds = ''
    for o in sub_order(ops) if callable(sub_order) else ops:
        for b in o.build:
            builds += '    build %s;\n' % b
    brt = [o.target for o in ops if o.kind == 'Address18_16']
    if brt:
        pat1 = [x for x in pat1 if x != brt[0]]
        patt = '(%s) ... & %s' % (' & '.join(pat1), brt[0])
    else:
        patt = (' & '.join(pat1) if pat1 else '') + ((' ; ' + ' & '.join(pat2)) if pat2 else '')
    text = ':%s %s is %s\n{\n%s%s}\n' % (mnem, ','.join(disp), patt, builds, body)
    return text


G.unimpl = set()


def generate(outdir):
    G.cons = []
    for inst in INSTS:
        ops0 = group_ops(inst['ops'])
        for ops in expansions(inst['name'], ops0, inst['opcode']):
            G.cons.append(build_constructor(inst, [copy_op(o) for o in ops]))
    write_outputs(outdir)


def copy_op(o):
    import copy
    return copy.copy(o)


def write_outputs(outdir):
    # tokens
    t = '# Generated by tools/gen_teak.py: do not edit.\n\ndefine token teakop (16)\n'
    for n, (lo, hi) in sorted(G.fixed_fields.items(), key=lambda x: (x[1], x[0])):
        t += '    %s = (%d,%d)\n' % (n, lo, hi)
    ex = ''
    attach = collections.OrderedDict()
    for n, (tok, lo, hi, sg, att, dec) in sorted(G.op_fields.items()):
        line = '    %s = (%d,%d)%s%s\n' % (n, lo, hi, ' signed' if sg else '', ' dec' if dec else '')
        if tok == 'teakop':
            t += line
        else:
            ex += line
        if att:
            attach.setdefault(tuple(att), []).append(n)
    t += ';\n\ndefine token teakex (16)\n' + ex + ';\n\n'
    for att, names in attach.items():
        t += 'attach variables [ %s ] [ %s ];\n' % (' '.join(names), ' '.join(att))
    open(os.path.join(outdir, 'teak_tokens.sinc'), 'w').write(t)
    # tables
    t = '# Generated by tools/gen_teak.py: do not edit.\n\n' + view_macros()
    for n, text in G.tables.items():
        t += text + '\n'
    open(os.path.join(outdir, 'teak_tables.sinc'), 'w').write(t)
    t = '# Generated by tools/gen_teak.py: do not edit.\n\n' + '\n'.join(G.cons)
    open(os.path.join(outdir, 'teak_insts.sinc'), 'w').write(t)
    print('%d constructors, %d tables, unimplemented: %s' % (len(G.cons), len(G.tables), ' '.join(sorted(G.unimpl))), file=sys.stderr)


if __name__ == '__main__':
    generate(sys.argv[1])
