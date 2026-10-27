"""Instruction semantics for the Teak generator.  Each function receives the Ctx and the prepared operands and returns
SLEIGH statements; the generator puts `build` statements for the operand tables in front of them (unless the function
clears o.build and builds them itself)."""
from teak_lib import *

EXPAND = {}          # instruction name -> operand kinds that are expanded to constants
REGSPLIT = {}        # instruction name -> Register indices that get their own constructor
SEM = {}


def sem(*names):
    def d(f):
        for n in names:
            SEM[n] = f
        return f
    return d


SIG = {}


def sig(name, *kinds):
    def d(f):
        SIG[(name,) + kinds] = f
        return f
    return d


def emit(c, inst, ops):
    ops = [o for o in ops if o.typ != 'Unused']
    kinds = tuple(o.kind if o.typ in ('At', 'AtNamed', 'Const') and o.kind else o.typ for o in ops)
    for o in ops:
        if o.typ == 'RnStep':
            pass
    kk = tuple(('RnStep' if o.typ == 'RnStep' else 'ArMem' if o.typ == 'ArMem' else 'ArpMem' if o.typ == 'ArpMem' else (o.kind or o.typ)) for o in ops)
    f = SIG.get((inst['name'],) + kk)
    if f is None:
        f = SEM.get(inst['name'])
    if f is None:
        return None, None
    r = f(c, ops)
    return r, None


# ---------------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------------
def full(o):
    """the full 5 byte accumulator (register name or field) behind operand o"""
    if hasattr(o, 'full'):
        return o.full
    return o.reg[:2]


def part(o):
    k = o.kind
    if k in ('Axl', 'Bxl', 'Abl'):
        return 'l'
    if k in ('Axh', 'Bxh', 'Abh'):
        return 'h'
    if k == 'Abe':
        return 'e'
    if k == 'Ablh':
        return 'lh'
    return 'full'


def L(*a):
    return ''.join('    %s\n' % x for x in a)


def acc40(o, v):
    """statement: v (local 8 byte) = sign extended accumulator"""
    return 'local %s:8 = sext(%s);\n' % (v, full(o))


def ctx_unit(o):
    return o.reg


def is_const(o):
    return hasattr(o, 'reg') and not o.reg.startswith(('Ax', 'Bx', 'Ab'))


def mul_text(unit, xs, ys, tag=''):
    """DoMultiplication(unit, xs, ys) with constant sign flags (xs, ys are Python bools)"""
    x, y, p, pe = ('x0', 'y0', 'p0', 'P0E') if unit == 0 else ('x1', 'y1', 'p1', 'P1E')
    my, mx = 'my%d%s' % (unit, tag), 'mx%d%s' % (unit, tag)
    if unit == 0:
        hw = ('    if (HWM == 1 || HWM == 3) goto <shr%d%s>;\n    if (HWM != 2) goto <ok%d%s>;\n    %s = %s & 0xff;\n    goto <ok%d%s>;\n'
              '  <shr%d%s>\n    %s = %s >> 8;\n  <ok%d%s>\n') % (unit, tag, unit, tag, my, my, unit, tag, unit, tag, my, my, unit, tag)
    else:
        hw = ('    if (HWM == 1) goto <shr%d%s>;\n    if (HWM < 2) goto <ok%d%s>;\n    %s = %s & 0xff;\n    goto <ok%d%s>;\n'
              '  <shr%d%s>\n    %s = %s >> 8;\n  <ok%d%s>\n') % (unit, tag, unit, tag, my, my, unit, tag, unit, tag, my, my, unit, tag)
    t = '    local %s:4 = zext(%s);\n%s' % (my, y, hw)
    t += '    local %s:4 = %s(%s);\n' % (mx, 'sext' if xs else 'zext', x)
    if ys:
        t += '    %s = sext(%s:2);\n' % (my, my)
    t += '    %s = %s * %s;\n' % (p, mx, my)
    t += '    %s = %s;\n' % (pe, ('%s[31,1]' % p) if (xs or ys) else '0')
    return t


def alm_ext(opname, v16, a='a'):
    """local a:8 = alm operand extension of the 16 bit value expression v16"""
    if opname in ('cmp', 'sub', 'add'):
        return '    local %s:8 = sext(%s);\n' % (a, v16)
    if opname in ('addh', 'subh'):
        return '    local %sw:4 = zext(%s) << 16;\n    local %s:8 = sext(%sw);\n' % (a, v16, a, a)
    return '    local %s:8 = zext(%s);\n' % (a, v16)


def alm_generic(opname, b, a='a'):
    """AlmGeneric: operand local a:8, destination accumulator b (a 5 byte varnode)"""
    t = ''
    if opname in ('or', 'and', 'xor'):
        sym = {'or': '|', 'and': '&', 'xor': '^'}[opname]
        t += '    local v:8 = sext(%s) %s %s;\n    SignExt40(v);\n    SetAccAndFlag(%s, v);\n' % (b, sym, a, b)
    elif opname == 'tst0':
        t += '    local v:8 = sext(%s) & 0xffff;\n    Z = ((v & %s) == 0);\n' % (b, a)
    elif opname == 'tst1':
        t += '    local v:8 = sext(%s) & 0xffff;\n    Z = ((v & ~%s) == 0);\n' % (b, a)
    elif opname in ('cmp', 'cmpu', 'sub', 'subl', 'subh', 'add', 'addl', 'addh'):
        fn = 'AddAcc' if opname in ('add', 'addl', 'addh') else 'SubAcc'
        t += '    local v:8 = sext(%s);\n    local r:8 = 0;\n    %s(r, v, %s);\n' % (b, fn, a)
        if opname in ('cmp', 'cmpu'):
            t += '    AccFlags(r);\n'
        else:
            t += '    SatAndSetAccAndFlag(%s, r);\n' % b
    elif opname == 'msu':
        t += ('    local v:8 = sext(%s);\n    local pr:8 = 0;\n    P40_0(pr);\n    local r:8 = 0;\n    SubAcc(r, v, pr);\n'
              '    SatAndSetAccAndFlag(%s, r);\n    x0 = %s:2;\n%s') % (b, b, a, mul_text(0, True, True))
    elif opname in ('sqr', 'sqra'):
        if opname == 'sqra':
            t += ('    local v:8 = sext(%s);\n    local pr:8 = 0;\n    P40_0(pr);\n    local r:8 = 0;\n    AddAcc(r, v, pr);\n'
                  '    SatAndSetAccAndFlag(%s, r);\n') % (b, b)
        t += '    x0 = %s:2;\n    y0 = x0;\n%s' % (a, mul_text(0, True, True))
    else:
        raise Exception(opname)
    return t


@sem('nop')
def _(c, ops):
    return ''


@sem('alm')
def _(c, ops):
    op, src, b = ops
    n = op.enumname
    bacc = full(b)
    if src.typ == 'RnStep':
        t = L('local v16:2 = %s;' % src.disp)
    elif hasattr(src, 'mem'):
        t = L('local v16:2 = %s;' % src.mem)
    else:   # Register
        t = reg_src_alm(c, src, op, bacc)
        return t
    return t + alm_ext(n, 'v16') + alm_generic(n, bacc)


def reg_src_alm(c, src, op, bacc):
    n = op.enumname
    src.build = []
    if getattr(src, 'enumname', None) in ('p0h', 'a0', 'a1'):
        nm = src.enumname
        if n in ('or', 'and', 'xor', 'add', 'cmp', 'sub'):
            if nm == 'p0h':
                t = '    local a:8 = 0;\n    P40_0(a);\n'
            else:
                t = '    local a:8 = sext(%s);\n' % nm
            return t + alm_generic(n, bacc)
        return L('local v16:2 = 0;') + (('    local a40:8 = 0;\n    P40_0(a40);\n    local a40s:8 = a40 >> 16;\n    v16 = a40s:2;\n' if nm == 'p0h' else '    v16 = %sl;\n' % nm)) + alm_ext(n, 'v16') + alm_generic(n, bacc)
    src.pat.append(src.rd)
    return '    build %s;\n    local v16:2 = %s;\n' % (src.rd, src.rd) + alm_ext(n, 'v16') + alm_generic(n, bacc)


REGSPLIT[(0x80A0, 0)] = [11, 24, 25]


# ---------------------------------------------------------------------------------------------------
# generic operand access
# ---------------------------------------------------------------------------------------------------
def loc(o):
    """varnode of a memory operand (table export)"""
    if hasattr(o, 'mem'):
        return o.mem
    return o.disp


def is_mem(o):
    return hasattr(o, 'mem') or o.typ == 'RnStep'


def bus_from_acc(o, sat, v='bv'):
    """statements that put the 16 bit bus value of accumulator part operand o into local v (RegToBus16 of l/h)"""
    a = full(o)
    p = part(o)
    if p == 'full':
        return '    local %s:2 = %sl;\n' % (v, a) if False else '    local %s:2 = %s[0,16];\n' % (v, a)
    t = ''
    if sat:
        t += '    local %sx:8 = 0;\n    GetSatAcc(%sx, %s);\n' % (v, v, a)
    else:
        t += '    local %sx:8 = sext(%s);\n' % (v, a)
    if p == 'l':
        t += '    local %s:2 = %sx:2;\n' % (v, v)
    elif p == 'h':
        t += '    local %ss:8 = %sx >> 16;\n    local %s:2 = %ss:2;\n' % (v, v, v, v)
    else:   # lh: half select bit
        t += ('    local %shh:1 = %s;\n    local %s:2 = %sx:2;\n    if (%shh == 0) goto <l%s>;\n    local %ss:8 = %sx >> 16;\n    %s = %ss:2;\n  <l%s>\n'
              % (v, o.half, v, v, v, v, v, v, v, v, v))
    return t


def bus_to_acc(o, v):
    """RegFromBus16(accumulator part, v): statements"""
    a = full(o)
    p = part(o)
    t = '    local %sa:8 = 0;\n' % v
    if p == 'full':
        t += '    %sa = sext(%s);\n' % (v, v)
    elif p == 'l':
        t += '    %sa = zext(%s);\n' % (v, v)
    elif p == 'h':
        t += '    local %sw:4 = zext(%s);\n    %sw = %sw << 16;\n    %sa = sext(%sw);\n' % (v, v, v, v, v, v)
    else:
        t += ('    local %shh:1 = %s;\n    %sa = zext(%s);\n    if (%shh == 0) goto <h%s>;\n    local %sw:4 = zext(%s);\n    %sw = %sw << 16;\n    %sa = sext(%sw);\n  <h%s>\n'
              % (v, o.half, v, v, v, v, v, v, v, v, v, v, v))
    t += '    SatAndSetAccAndFlag(%s, %sa);\n' % (a, v)
    return t


def as_reg16(o, sat=False, v='rv'):
    """statements reading a Register/RnOld/accumulator-part operand into a 16 bit local; builds tables as needed"""
    if o.kind == 'Register':
        if o.enumname:
            nm = o.enumname
            if nm == 'p0h':
                return ('    local %sx:8 = 0;\n    P40_0(%sx);\n    local %sy:8 = %sx >> 16;\n    local %s:2 = %sy:2;\n' % (v, v, v, v, v, v))
            if nm in ('a0', 'a1'):
                return '    local %s:2 = %s[0,16];\n' % (v, nm)
            if nm == 'pc':
                return '    local %s4:4 = inst_next;\n    %s4 = %s4 >> 1;\n    local %s:2 = %s4:2;\n' % (v, v, v, v, v)
            if nm in ('b0h', 'b1h', 'b0l', 'b1l', 'a0l', 'a1l', 'a0h', 'a1h'):
                return '    local %s:2 = %s;\n' % (v, nm)
            raise Exception('register %s' % nm)
        o.pat.append(o.rds if sat else o.rd)
        return '    build %s;\n    local %s:2 = %s;\n' % (o.rds if sat else o.rd, v, o.rds if sat else o.rd)
    if o.kind in ('RnOld', 'Rn', 'R45', 'R0123'):
        return '    local %s:2 = %s;\n' % (v, o.reg)
    return bus_from_acc(o, sat, v)


def wr_reg(o, v):
    """statements writing 16 bit local v into a Register / RnOld / accumulator operand (RegFromBus16)"""
    if o.kind == 'Register':
        o.pat.append(o.wr)
        return '    wb = %s;\n    build %s;\n' % (v, o.wr)
    if o.kind in ('RnOld', 'Rn', 'R45', 'R0123'):
        return '    %s = %s;\n' % (o.reg, v)
    if o.kind in ('SttMod', 'ArArp', 'ArArpSttMod'):
        o.pat.append(o.wr)
        return '    wb = %s;\n    build %s;\n' % (v, o.wr)
    if o.kind in ('Ax', 'Bx', 'Ab'):
        return '    local %sa:8 = sext(%s);\n    SatAndSetAccAndFlag(%s, %sa);\n' % (v, v, full(o), v)
    return bus_to_acc(o, v)


def rd_ctl(o, v='cv'):
    o.pat.append(o.rd)
    return '    build %s;\n    local %s:2 = %s;\n' % (o.rd, v, o.rd)


def noauto(*ops):
    for o in ops:
        o.build = []


# ---------------------------------------------------------------------------------------------------
# ALM / ALU / ALB
# ---------------------------------------------------------------------------------------------------
@sem('alm_r6')
def _(c, ops):
    op, b = ops
    return L('local v16:2 = r6;') + alm_ext(op.enumname, 'v16') + alm_generic(op.enumname, full(b))


@sem('alu')
def _(c, ops):
    op, src, b = ops
    n = op.enumname
    if src.kind == 'Imm16':
        t = L('local v16:2 = %s;' % src.imm)
    elif src.kind == 'Imm8':
        t = L('local v16:2 = %s;' % src.imm)
    else:
        t = L('local v16:2 = %s;' % loc(src))
    bacc = full(b)
    if src.kind == 'Imm8' and n == 'and':
        t += L('local keep:5 = %s & 0xff00;' % bacc)
        t += alm_ext(n, 'v16') + alm_generic(n, bacc)
        t += L('%s = (%s & 0xffffffff00ff) | keep;' % (bacc, bacc))
        return t
    return t + alm_ext(n, 'v16') + alm_generic(n, bacc)


@sem('or_', 'and_')
def _(c, ops):
    sym = '|' if c.name == 'or_' else '&'
    *srcs, d = ops
    return (L('local v:8 = sext(%s) %s sext(%s);' % (full(srcs[0]), sym, full(srcs[1])), 'SetAccAndFlag(%s, v);' % full(d)))


def alb_generic(n, a, bv):
    """GenericAlb: a, bv are 2 byte locals; leaves result in local res:2 and sets flags"""
    t = '    local res:2 = 0;\n'
    if n == 'set':
        t += '    res = %s | %s;\n    M = res[15,1];\n' % (a, bv)
    elif n == 'rst':
        t += '    res = (~%s) & %s;\n    M = res[15,1];\n' % (a, bv)
    elif n == 'chng':
        t += '    res = %s ^ %s;\n    M = res[15,1];\n' % (a, bv)
    elif n == 'addv':
        t += ('    local r32:4 = zext(%s) + zext(%s);\n    C = r32[16,1];\n    local s32:4 = sext(%s) + sext(%s);\n    M = s32[31,1];\n'
              '    res = r32:2;\n') % (bv, a, bv, a)
    elif n in ('cmpv', 'subv'):
        t += ('    local r32:4 = zext(%s) - zext(%s);\n    C = r32[16,1];\n    local s32:4 = sext(%s) - sext(%s);\n    M = s32[31,1];\n'
              '    res = r32:2;\n') % (bv, a, bv, a)
    elif n == 'tst0':
        t += '    if ((%s & %s) == 0) goto <t0>;\n    res = 1;\n  <t0>\n' % (a, bv)
    elif n == 'tst1':
        t += '    if ((%s & (~%s)) == 0) goto <t1>;\n    res = 1;\n  <t1>\n' % (a, bv)
    t += '    Z = (res == 0);\n'
    return t


ALB_MOD = ('set', 'rst', 'chng', 'addv', 'subv')
REGSPLIT[(0x81E0, 0)] = list(range(16, 20)) + list(range(26, 30))


@sem('alb')
def _(c, ops):
    op, imm, dst = ops
    n = op.enumname
    t = L('local a16:2 = %s;' % imm.imm)
    if dst.typ == 'RnStep' or hasattr(dst, 'mem'):
        t += L('local bv:2 = %s;' % loc(dst)) + alb_generic(n, 'a16', 'bv')
        if n in ALB_MOD:
            t += L('%s = res;' % loc(dst))
        return t
    if dst.kind == 'SttMod':
        t += rd_ctl(dst, 'bv') + alb_generic(n, 'a16', 'bv')
        if n in ALB_MOD:
            noauto(dst)
            t += wr_reg(dst, 'res')
        return t
    # Register
    nm = getattr(dst, 'enumname', None)
    if nm:      # accumulator part: direct access without flags / saturation
        t += L('local bv:2 = %s;' % nm) + alb_generic(n, 'a16', 'bv')
        if n in ALB_MOD:
            t += L('%s = res;' % nm)
        return t
    t += as_reg16(dst, False, 'bv') + alb_generic(n, 'a16', 'bv')
    if n in ALB_MOD:
        t += wr_reg(dst, 'res')
    return t


@sem('alb_r6')
def _(c, ops):
    op, imm = ops
    n = op.enumname
    t = L('local a16:2 = %s;' % imm.imm, 'local bv:2 = r6;') + alb_generic(n, 'a16', 'bv')
    if n in ALB_MOD:
        t += L('r6 = res;')
    return t


# ---------------------------------------------------------------------------------------------------
# accumulator arithmetic
# ---------------------------------------------------------------------------------------------------
def p40(px):
    return 'P40_%s' % ('0' if px.reg == 'p0' else '1')


def acc_or_prod(o, v):
    """local v:8 = 40 bit value of an accumulator or product operand"""
    if o.kind == 'Px':
        return '    local %s:8 = 0;\n    %s(%s);\n' % (v, p40(o), v)
    return '    local %s:8 = sext(%s);\n' % (v, full(o))


@sem('add', 'sub')
def _(c, ops):
    a, b = ops
    fn = 'AddAcc' if c.name == 'add' else 'SubAcc'
    return (acc_or_prod(a, 'va') + acc_or_prod(b, 'vb') +
            L('local r:8 = 0;', '%s(r, vb, va);' % fn, 'SatAndSetAccAndFlag(%s, r);' % full(b)))


@sem('add_p1', 'sub_p1')
def _(c, ops):
    b, = ops
    fn = 'AddAcc' if c.name == 'add_p1' else 'SubAcc'
    return L('local va:8 = 0;', 'P40_1(va);', 'local vb:8 = sext(%s);' % full(b), 'local r:8 = 0;', '%s(r, vb, va);' % fn,
             'SatAndSetAccAndFlag(%s, r);' % full(b))


@sem('cmp')
def _(c, ops):
    a, b = ops
    return L('local va:8 = sext(%s);' % full(a), 'local vb:8 = sext(%s);' % full(b), 'local r:8 = 0;', 'SubAcc(r, vb, va);', 'AccFlags(r);')


@sem('cmp_b0_b1')
def _(c, ops):
    return L('local va:8 = sext(b0);', 'local vb:8 = sext(b1);', 'local r:8 = 0;', 'SubAcc(r, vb, va);', 'AccFlags(r);')


@sem('cmp_b1_b0')
def _(c, ops):
    return L('local va:8 = sext(b1);', 'local vb:8 = sext(b0);', 'local r:8 = 0;', 'SubAcc(r, vb, va);', 'AccFlags(r);')


@sem('cmp_p1_to')
def _(c, ops):
    b, = ops
    return L('local va:8 = 0;', 'P40_1(va);', 'local vb:8 = sext(%s);' % full(b), 'local r:8 = 0;', 'SubAcc(r, vb, va);', 'AccFlags(r);')


@sem('lim')
def _(c, ops):
    a, b = ops
    return L('local v:8 = sext(%s);' % full(a), 'SatAcc(v);', 'SetAccAndFlag(%s, v);' % full(b))


@sem('pacr1')
def _(c, ops):
    a, = ops
    return L('local v:8 = 0;', 'P40_1(v);', 'local r:8 = 0;', 'local k:8 = 0x8000;', 'AddAcc(r, v, k);', 'SatAndSetAccAndFlag(%s, r);' % full(a))


def moda_body(opn, a):
    acc = full(a)
    v = '    local v:8 = sext(%s);\n' % acc
    if opn in ('shr', 'shr4', 'shl', 'shl4'):
        sv = {'shr': '0xffff', 'shr4': '0xfffc', 'shl': '1', 'shl4': '4'}[opn]
        return v + '    local shv:2 = %s;\n    ShiftBus40(%s, v, shv);\n' % (sv, acc)
    if opn == 'ror':
        return (v + '    local vm:8 = v & 0xffffffffff;\n    local oc:8 = zext(C);\n    C = vm[0,1];\n    vm = (vm >> 1) | (oc << 39);\n'
                '    SignExt40(vm);\n    SetAccAndFlag(%s, vm);\n' % acc)
    if opn == 'rol':
        return (v + '    local oc:8 = zext(C);\n    C = v[39,1];\n    v = (v << 1) | oc;\n    SignExt40(v);\n    SetAccAndFlag(%s, v);\n' % acc)
    if opn == 'clr':
        return '    local v:8 = 0;\n    SatAndSetAccAndFlag(%s, v);\n' % acc
    if opn == 'clrr':
        return '    local v:8 = 0x8000;\n    SatAndSetAccAndFlag(%s, v);\n' % acc
    if opn == 'not':
        return v + '    v = ~v;\n    SetAccAndFlag(%s, v);\n' % acc
    if opn == 'neg':
        return (v + '    C = (v != 0);\n    V = (v == 0xffffff8000000000);\n    VL = VL | V;\n    v = 0 - v;\n    SignExt40(v);\n'
                '    SatAndSetAccAndFlag(%s, v);\n' % acc)
    if opn == 'rnd':
        return v + '    local k:8 = 0x8000;\n    local r:8 = 0;\n    AddAcc(r, v, k);\n    SatAndSetAccAndFlag(%s, r);\n' % acc
    if opn == 'pacr':
        return ('    local v:8 = 0;\n    P40_0(v);\n    local k:8 = 0x8000;\n    local r:8 = 0;\n    AddAcc(r, v, k);\n'
                '    SatAndSetAccAndFlag(%s, r);\n' % acc)
    if opn in ('inc', 'dec'):
        fn = 'AddAcc' if opn == 'inc' else 'SubAcc'
        return v + '    local k:8 = 1;\n    local r:8 = 0;\n    %s(r, v, k);\n    SatAndSetAccAndFlag(%s, r);\n' % (fn, acc)
    if opn == 'copy':
        other = 'a1' if acc == 'a0' else 'a0'
        return '    local v:8 = sext(%s);\n    SatAndSetAccAndFlag(%s, v);\n' % (other, acc)
    raise Exception(opn)


EXPAND['moda4'] = ('Ax',)
EXPAND['moda3'] = ('Bx',)


@sem('moda4', 'moda3')
def _(c, ops):
    op, a, cond = ops
    return cond_skip(cond) + moda_body(op.enumname, a)


def double_clr(a, b):
    """FilterDoubleClr on register names"""
    if a == 'b0':
        b = 'b1'
    elif a == 'b1':
        b = 'b0'
    elif a == 'a0':
        if b == 'a0':
            b = 'a1'
    else:
        b = 'b1' if b == 'b1' else 'b0'
    return a, b


EXPAND['clr'] = ('Ab',)
EXPAND['clrr'] = ('Ab',)


@sem('clr', 'clrr')
def _(c, ops):
    a, b = ops
    a2, b2 = double_clr(a.reg, b.reg)
    k = '0' if c.name == 'clr' else '0x8000'
    return (L('local v:8 = %s;' % k, 'SatAndSetAccAndFlag(%s, v);' % a2, 'v = %s;' % k, 'SatAndSetAccAndFlag(%s, v);' % b2))


@sem('divs')
def _(c, ops):
    m, b = ops
    bacc = full(b)
    return L('local da:8 = zext(%s);' % loc(m), 'local db:8 = sext(%s);' % bacc, 'local value:8 = db - (da << 15);',
             'local nv:8 = 0;', 'if (value s>= 0) goto <pos>;', 'nv = db << 1;', 'goto <set>;', '<pos>', 'nv = (value << 1) + 1;', '<set>',
             'SignExt40(nv);', 'SetAccAndFlag(%s, nv);' % bacc)


@sem('swap')
def _(c, ops):
    st, = ops
    i = st.val
    # (src0, dst0, src1, dst1), with the double exchanges storing both
    t = {0: ('a0', 'b0', 'b0', 'a0'), 1: ('a0', 'b1', 'b1', 'a0'), 2: ('a1', 'b0', 'b0', 'a1'), 3: ('a1', 'b1', 'b1', 'a1'),
         4: None, 5: None,
         6: ('a0', 'b0', 'b0', 'a1'), 7: ('a0', 'b1', 'b1', 'a1'), 8: ('a1', 'b0', 'b0', 'a0'), 9: ('a1', 'b1', 'b1', 'a0'),
         10: ('a0', 'b1', 'b0', 'a0'), 11: ('a1', 'b1', 'b0', 'a1'), 12: ('a0', 'b0', 'b1', 'a0'), 13: ('a1', 'b0', 'b1', 'a1')}
    pre = ''
    if i == 4:
        pre = L('local u:8 = sext(a1);', 'local w:8 = sext(b1);', 'SatAndSetAccAndFlag(a1, w);', 'SatAndSetAccAndFlag(b1, u);')
        s0, d0, s1, d1 = 'a0', 'b0', 'b0', 'a0'
    elif i == 5:
        pre = L('local u:8 = sext(a1);', 'local w:8 = sext(b0);', 'SatAndSetAccAndFlag(a1, w);', 'SatAndSetAccAndFlag(b0, u);')
        s0, d0, s1, d1 = 'a0', 'b1', 'b1', 'a0'
    else:
        s0, d0, s1, d1 = t[i]
    return pre + L('local u0:8 = sext(%s);' % s0, 'local u1:8 = sext(%s);' % s1, 'SatAndSetAccAndFlag(%s, u0);' % d0,
                   'SatAndSetAccAndFlag(%s, u1);' % d1)


# ---------------------------------------------------------------------------------------------------
# moves
# ---------------------------------------------------------------------------------------------------
def src16(o, sat, v='sv16'):
    """statements that read operand o (memory, Register, partial accumulator, RnOld ...) into 16 bit local v"""
    if is_mem(o):
        return '    local %s:2 = %s;\n' % (v, loc(o))
    if o.kind in ('SttMod', 'ArArp', 'ArArpSttMod'):
        return rd_ctl(o, v)
    if o.kind == 'Imm16' or o.kind in ('Imm8', 'Imm4', 'Imm5', 'Imm2'):
        return '    local %s:2 = %s;\n' % (v, o.imm)
    if o.kind in ('Imm8s', 'Imm7s', 'Imm5s'):
        return '    local %s:2 = %s;\n' % (v, o.imm)
    return as_reg16(o, sat, v)


def ar_addrs(o, v='ap'):
    """ArMem operand -> locals v1 (address) and v2 (offset address)"""
    return ('    local %sk:4 = %s;\n    local %s1:2 = %sk:2;\n    local %sk2:4 = %sk >> 16;\n    local %s2:2 = %sk2:2;\n'
            % (v, o.disp, v, v, v, v, v, v))


def mov_to(src_sat, srcop, dst):
    return src16(srcop, src_sat) + wr_reg(dst, 'sv16')


MOV_SIGS = [
    # (src kind, dst kind, saturating read)
]


@sig('mov', 'Ab', 'Ab')
def _(c, ops):
    a, b = ops
    return L('local v:8 = sext(%s);' % full(a), 'SatAndSetAccAndFlag(%s, v);' % full(b))


for _k in ('Ablh', 'Axl'):
    for _m in ('MemImm8', 'MemImm16', 'MemR7Imm16', 'MemR7Imm7s'):
        @sig('mov', _k, _m)
        def _(c, ops):
            a, m = ops
            return src16(a, True, 'sv16') + L('%s = sv16;' % loc(m))


for _k in ('Ab', 'Ablh', 'Ax', 'Bx'):
    for _m in ('MemImm8', 'MemImm16', 'MemR7Imm16', 'MemR7Imm7s', 'RnStep'):
        @sig('mov', _m, _k)
        def _(c, ops):
            m, b = ops
            return src16(m, False, 'sv16') + wr_reg(b, 'sv16')


for _m in ('MemImm8', 'MemImm16', 'MemR7Imm16', 'MemR7Imm7s', 'RnStep'):
    @sig('mov', _m, 'RnOld')
    def _(c, ops):
        m, b = ops
        return src16(m, False, 'sv16') + wr_reg(b, 'sv16')


@sig('mov', 'RnStep', 'Register')
def _(c, ops):
    m, b = ops
    return src16(m, False, 'sv16') + wr_reg(b, 'sv16')


@sig('mov_eu', 'MemImm8', 'Axh')
def _(c, ops):
    m, a = ops
    return L('local val:2 = %s;' % loc(m), 'local v:8 = (sext(%s) & 0xffffffff00000000) | (zext(val) << 16);' % full(a),
             'SetAccAndFlag(%s, v);' % full(a))


@sig('mov_sv', 'MemImm8')
def _(c, ops):
    return L('sv = %s;' % loc(ops[0]))


@sig('mov_sv', 'Imm8s')
def _(c, ops):
    return L('sv = %s;' % ops[0].imm)


@sig('mov_sv_to', 'MemImm8')
def _(c, ops):
    return L('%s = sv;' % loc(ops[0]))


@sig('mov', 'Imm16', 'Bx')
def _(c, ops):
    i, b = ops
    return L('local sv16:2 = %s;' % i.imm) + wr_reg(b, 'sv16')


@sig('mov', 'Imm16', 'Register')
def _(c, ops):
    i, b = ops
    return L('local sv16:2 = %s;' % i.imm) + wr_reg(b, 'sv16')


@sig('mov', 'Imm16', 'ArArp')
def _(c, ops):
    i, b = ops
    return L('local sv16:2 = %s;' % i.imm) + wr_reg(b, 'sv16')


@sig('mov', 'Imm16', 'SttMod')
def _(c, ops):
    i, b = ops
    return L('local sv16:2 = %s;' % i.imm) + wr_reg(b, 'sv16')


@sig('mov', 'Imm8s', 'Axh')
def _(c, ops):
    i, b = ops
    return L('local sv16:2 = %s;' % i.imm) + wr_reg(b, 'sv16')


@sig('mov', 'Imm8s', 'RnOld')
def _(c, ops):
    i, b = ops
    return L('%s = %s;' % (b.reg, i.imm))


@sig('mov', 'Imm8', 'Axl')
def _(c, ops):
    i, b = ops
    return L('local sv16:2 = %s;' % i.imm) + wr_reg(b, 'sv16')


for _n, _r in (('mov_ext0', 'ext0'), ('mov_ext1', 'ext1'), ('mov_ext2', 'ext2'), ('mov_ext3', 'ext3')):
    @sig(_n, 'Imm8s')
    def _(c, ops, _r=_r):
        return L('%s = %s;' % (_r, ops[0].imm))


@sig('mov_r6', 'Imm16')
def _(c, ops):
    return L('r6 = %s;' % ops[0].imm)


@sig('mov_repc', 'Imm16')
def _(c, ops):
    return L('repc = %s;' % ops[0].imm)


@sig('mov_stepi0', 'Imm16')
def _(c, ops):
    return L('stepi0 = %s;' % ops[0].imm)


@sig('mov_stepj0', 'Imm16')
def _(c, ops):
    return L('stepj0 = %s;' % ops[0].imm)


@sig('mov_prpage', 'Imm4')
def _(c, ops):
    return L('prpage = %s;' % ops[0].imm)


@sig('mov_icr', 'Imm5')
def _(c, ops):
    return L('local v:2 = 0;', 'Compose_icr(v);', 'v = (v & 0xffe0) | %s;' % ops[0].imm, 'Decompose_icr(v);')


@sig('mov_icr', 'Register')
def _(c, ops):
    return src16(ops[0], True, 'sv16') + L('Decompose_icr(sv16);')


@sig('mov_icr_to', 'Ab')
def _(c, ops):
    return L('local v:2 = 0;', 'Compose_icr(v);') + wr_reg(ops[0], 'v')


@sig('mov_mixp', 'Register')
def _(c, ops):
    return src16(ops[0], True, 'sv16') + L('mixp = sv16;')


@sig('mov_mixp_to', 'Register')
def _(c, ops):
    return L('local sv16:2 = mixp;') + wr_reg(ops[0], 'sv16')


@sig('mov_mixp_to', 'Bx')
def _(c, ops):
    return L('local sv16:2 = mixp;') + wr_reg(ops[0], 'sv16')


@sig('mov_mixp_r6')
def _(c, ops):
    return L('r6 = mixp;')


@sig('mov_r6_mixp')
def _(c, ops):
    return L('mixp = r6;')


@sig('mov_memsp_to', 'Register')
def _(c, ops):
    return L('local sv16:2 = *[DATA]:2 sp;') + wr_reg(ops[0], 'sv16')


@sig('mov_memsp_r6')
def _(c, ops):
    return L('r6 = *[DATA]:2 sp;')


@sig('mov', 'RnOld', 'MemImm8')
def _(c, ops):
    a, m = ops
    return L('%s = %s;' % (loc(m), a.reg))


@sig('mov', 'Register', 'RnStep')
def _(c, ops):
    a, m = ops
    m.build = []
    return src16(a, True, 'sv16') + L('build %s;' % m.disp, '%s = sv16;' % loc(m))


@sig('mov', 'Register', 'Register')
def _(c, ops):
    a, b = ops
    nm = getattr(a, 'enumname', None)
    b.pat.append(b.num)
    if nm == 'p0h':
        # destination: a1 if the low bit of the register number is set, else a0
        return L('local v:8 = 0;', 'P40_0(v);', 'local bn:1 = %s;' % b.num, 'if ((bn & 1) == 0) goto <d0>;', 'SatAndSetAccAndFlag(a1, v);', 'goto <dn>;', '<d0>',
                 'SatAndSetAccAndFlag(a0, v);', '<dn>')
    if nm == 'pc':
        # pc is the address of the next instruction; a0/a1 (24, 25) get the whole pc
        return (L('local pcw:4 = inst_next;', 'pcw = pcw >> 1;', 'local pcv:3 = pcw:3;', 'local sv16:2 = pcv:2;', 'local v:8 = zext(pcv);',
                  'local bn:1 = %s;' % b.num, 'if (bn != 24 && bn != 25) goto <ng>;', 'if (bn != 25) goto <g0>;',
                  'SatAndSetAccAndFlag(a1, v);', 'goto <dn>;', '<g0>', 'SatAndSetAccAndFlag(a0, v);', 'goto <dn>;', '<ng>') + wr_reg(b, 'sv16') + L('<dn>'))
    return src16(a, True, 'sv16') + wr_reg(b, 'sv16')


@sig('mov', 'Register', 'Bx')
def _(c, ops):
    a, b = ops
    nm = getattr(a, 'enumname', None)
    if nm == 'p0h':
        return L('local v:8 = 0;', 'P40_0(v);', 'SatAndSetAccAndFlag(%s, v);' % full(b))
    if nm in ('a0', 'a1'):
        return L('local v:8 = sext(%s);' % nm, 'SatAndSetAccAndFlag(%s, v);' % full(b))
    return src16(a, True, 'sv16') + wr_reg(b, 'sv16')


REGSPLIT[(0x5EC0, 0)] = [11, 24, 25]
REGSPLIT[(0x5800, 0)] = [11, 12]


@sig('mov_repc_to', 'Ab')
def _(c, ops):
    return L('local sv16:2 = repc;') + wr_reg(ops[0], 'sv16')


for _n, _r in (('mov_x0_to', 'x0'), ('mov_x1_to', 'x1'), ('mov_y1_to', 'y1')):
    @sig(_n, 'Ab')
    def _(c, ops, _r=_r):
        return L('local sv16:2 = %s;' % _r) + wr_reg(ops[0], 'sv16')

for _n, _r in (('mov_x0', 'x0'), ('mov_x1', 'x1'), ('mov_y1', 'y1')):
    @sig(_n, 'Abl')
    def _(c, ops, _r=_r):
        return src16(ops[0], True, 'sv16') + L('%s = sv16;' % _r)


@sig('mov_a0h_stepi0')
def _(c, ops):
    return L('local v:8 = 0;', 'GetSatAcc(v, a0);', 'local vs:8 = v >> 16;', 'stepi0 = vs:2;')


@sig('mov_a0h_stepj0')
def _(c, ops):
    return L('local v:8 = 0;', 'GetSatAcc(v, a0);', 'local vs:8 = v >> 16;', 'stepj0 = vs:2;')


@sig('mov_stepi0_a0h')
def _(c, ops):
    return L('local sv16:2 = stepi0;', 'local w:4 = zext(sv16);', 'w = w << 16;', 'local v:8 = sext(w);', 'SatAndSetAccAndFlag(a0, v);')


@sig('mov_stepj0_a0h')
def _(c, ops):
    return L('local sv16:2 = stepj0;', 'local w:4 = zext(sv16);', 'w = w << 16;', 'local v:8 = sext(w);', 'SatAndSetAccAndFlag(a0, v);')


@sig('mov_prpage', 'Abl')
def _(c, ops):
    return L('local v:8 = sext(%s);' % full(ops[0]), 'local pv:2 = v:2;', 'prpage = pv & 0xf;')


@sig('mov_repc', 'Abl')
def _(c, ops):
    return src16(ops[0], True, 'sv16') + L('repc = sv16;')


@sig('mov_prpage_to', 'Abl')
def _(c, ops):
    return L('local sv16:2 = prpage;') + wr_reg(ops[0], 'sv16')


@sig('mov_repc_to', 'Abl')
def _(c, ops):
    return L('local sv16:2 = repc;') + wr_reg(ops[0], 'sv16')


@sig('mov', 'Abl', 'ArArp')
def _(c, ops):
    return src16(ops[0], True, 'sv16') + wr_reg(ops[1], 'sv16')


@sig('mov', 'Abl', 'SttMod')
def _(c, ops):
    return src16(ops[0], True, 'sv16') + wr_reg(ops[1], 'sv16')


@sig('mov', 'ArArp', 'Abl')
def _(c, ops):
    return src16(ops[0], False, 'sv16') + wr_reg(ops[1], 'sv16')


@sig('mov', 'SttMod', 'Abl')
def _(c, ops):
    return src16(ops[0], False, 'sv16') + wr_reg(ops[1], 'sv16')


@sig('mov_repc_to', 'ArMem')
def _(c, ops):
    return ar_addrs(ops[0]) + L('*[DATA]:2 ap1 = repc;')


@sig('mov', 'ArArp', 'ArMem')
def _(c, ops):
    return ar_addrs(ops[1]) + src16(ops[0], False, 'sv16') + L('*[DATA]:2 ap1 = sv16;')


@sig('mov', 'SttMod', 'ArMem')
def _(c, ops):
    return ar_addrs(ops[1]) + src16(ops[0], False, 'sv16') + L('*[DATA]:2 ap1 = sv16;')


@sig('mov_repc', 'ArMem')
def _(c, ops):
    return ar_addrs(ops[0]) + L('repc = *[DATA]:2 ap1;')


@sig('mov', 'ArMem', 'ArArp')
def _(c, ops):
    return ar_addrs(ops[0]) + L('local sv16:2 = *[DATA]:2 ap1;') + wr_reg(ops[1], 'sv16')


@sig('mov', 'ArMem', 'SttMod')
def _(c, ops):
    return ar_addrs(ops[0]) + L('local sv16:2 = *[DATA]:2 ap1;') + wr_reg(ops[1], 'sv16')


@sig('mov_repc_to', 'MemR7Imm16')
def _(c, ops):
    return L('%s = repc;' % loc(ops[0]))


@sig('mov', 'ArArpSttMod', 'MemR7Imm16')
def _(c, ops):
    return src16(ops[0], False, 'sv16') + L('%s = sv16;' % loc(ops[1]))


@sig('mov_repc', 'MemR7Imm16')
def _(c, ops):
    return L('repc = %s;' % loc(ops[0]))


@sig('mov', 'MemR7Imm16', 'ArArpSttMod')
def _(c, ops):
    return L('local sv16:2 = %s;' % loc(ops[0])) + wr_reg(ops[1], 'sv16')


@sig('mov_pc', 'Ax')
def _(c, ops):
    return L('local v:8 = sext(%s);' % full(ops[0]), 'local t:3 = v:3;', 'goto [t];')


@sig('mov_pc', 'Bx')
def _(c, ops):
    return L('local v:8 = sext(%s);' % full(ops[0]), 'local t:3 = v:3;', 'goto [t];')


@sig('mov_p0h_to', 'Bx')
def _(c, ops):
    return L('local v:8 = 0;', 'P40_0(v);', 'local vs:8 = v >> 16;', 'local sv16:2 = vs:2;') + wr_reg(ops[0], 'sv16')


@sig('mov_p0h_to', 'Register')
def _(c, ops):
    return L('local v:8 = 0;', 'P40_0(v);', 'local vs:8 = v >> 16;', 'local sv16:2 = vs:2;') + wr_reg(ops[0], 'sv16')


@sig('mov_p0h_r6')
def _(c, ops):
    return L('local v:8 = 0;', 'P40_0(v);', 'local vs:8 = v >> 16;', 'r6 = vs:2;')


@sig('mov_p0', 'Ab')
def _(c, ops):
    return L('local v:8 = 0;', 'GetSatAcc(v, %s);' % full(ops[0]), 'p0 = v:4;', 'P0E = p0[31,1];')


@sig('mov_p1_to', 'Ab')
def _(c, ops):
    return L('local v:8 = 0;', 'P40_1(v);', 'SatAndSetAccAndFlag(%s, v);' % full(ops[0]))


@sig('mov_r6_to', 'Bx')
def _(c, ops):
    return L('local sv16:2 = r6;') + wr_reg(ops[0], 'sv16')


@sig('mov_r6_to', 'Register')
def _(c, ops):
    return L('local sv16:2 = r6;') + wr_reg(ops[0], 'sv16')


@sig('mov_r6', 'Register')
def _(c, ops):
    return src16(ops[0], True, 'sv16') + L('r6 = sv16;')


@sig('mov_r6_to', 'RnStep')
def _(c, ops):
    ops[0].build = []
    return L('local sv16:2 = r6;', 'build %s;' % ops[0].disp, '%s = sv16;' % loc(ops[0]))


@sig('mov_r6', 'RnStep')
def _(c, ops):
    return L('r6 = %s;' % loc(ops[0]))


@sig('mov2', 'Px', 'ArMem')
def _(c, ops):
    p, m = ops
    return ar_addrs(m) + L('local v:4 = %s;' % p.reg, '*[DATA]:2 ap2 = v:2;', 'local vh:4 = v >> 16;', '*[DATA]:2 ap1 = vh:2;')


@sig('mov2s', 'Px', 'ArMem')
def _(c, ops):
    p, m = ops
    return ar_addrs(m) + L('local v:8 = 0;', '%s(v);' % p40(p), '*[DATA]:2 ap2 = v:2;', 'local vh:8 = v >> 16;', '*[DATA]:2 ap1 = vh:2;')


@sig('mov2', 'ArMem', 'Px')
def _(c, ops):
    m, p = ops
    return ar_addrs(m) + L('local l:2 = *[DATA]:2 ap2;', 'local h:2 = *[DATA]:2 ap1;', 'local v:4 = (zext(h) << 16) | zext(l);',
                           '%s = v;' % p.reg, '%s = v[31,1];' % ('P0E' if p.reg == 'p0' else 'P1E'))


@sig('mova', 'Ab', 'ArMem')
def _(c, ops):
    a, m = ops
    return ar_addrs(m) + L('local v:8 = 0;', 'GetSatAcc(v, %s);' % full(a), '*[DATA]:2 ap2 = v:2;', 'local vh:8 = v >> 16;', '*[DATA]:2 ap1 = vh:2;')


@sig('mova', 'ArMem', 'Ab')
def _(c, ops):
    m, b = ops
    return ar_addrs(m) + L('local l:2 = *[DATA]:2 ap2;', 'local h:2 = *[DATA]:2 ap1;', 'local w:4 = (zext(h) << 16) | zext(l);',
                           'local v:8 = sext(w);', 'SatAndSetAccAndFlag(%s, v);' % full(b))


# ---------------------------------------------------------------------------------------------------
# stack
# ---------------------------------------------------------------------------------------------------
def push16(v):
    return L('sp = sp - 1;', '*[DATA]:2 sp = %s;' % v)


def pop16(v):
    return L('local %s:2 = *[DATA]:2 sp;' % v, 'sp = sp + 1;')


@sig('push', 'Imm16')
def _(c, ops):
    return push16(ops[0].imm)


@sig('push', 'Register')
def _(c, ops):
    return src16(ops[0], True, 'sv16') + push16('sv16')


@sig('push', 'Abe')
def _(c, ops):
    a = ops[0]
    return L('local v:8 = 0;', 'GetSatAcc(v, %s);' % full(a), 'local vh:8 = v >> 32;', 'local sv16:2 = vh:2;') + push16('sv16')


@sig('push', 'ArArpSttMod')
def _(c, ops):
    return src16(ops[0], False, 'sv16') + push16('sv16')


@sig('push_prpage')
def _(c, ops):
    return L('local sv16:2 = prpage;') + push16('sv16')


@sig('push', 'Px')
def _(c, ops):
    p = ops[0]
    return (L('local v:8 = 0;', '%s(v);' % p40(p), 'local lo:2 = v:2;', 'local vh:8 = v >> 16;', 'local hi:2 = vh:2;') +
            push16('lo') + push16('hi'))


for _n, _r in (('push_r6', 'r6'), ('push_repc', 'repc'), ('push_x0', 'x0'), ('push_x1', 'x1'), ('push_y1', 'y1')):
    @sig(_n)
    def _(c, ops, _r=_r):
        return L('local sv16:2 = %s;' % _r) + push16('sv16')


@sig('pusha', 'Ax')
def _(c, ops):
    return (L('local v:8 = 0;', 'GetSatAcc(v, %s);' % full(ops[0]), 'local lo:2 = v:2;', 'local vh:8 = v >> 16;', 'local hi:2 = vh:2;') +
            push16('lo') + push16('hi'))


@sig('pusha', 'Bx')
def _(c, ops):
    return (L('local v:8 = 0;', 'GetSatAcc(v, %s);' % full(ops[0]), 'local lo:2 = v:2;', 'local vh:8 = v >> 16;', 'local hi:2 = vh:2;') +
            push16('lo') + push16('hi'))


@sig('pop', 'Register')
def _(c, ops):
    return pop16('sv16') + wr_reg(ops[0], 'sv16')


@sig('pop', 'Abe')
def _(c, ops):
    a = full(ops[0])
    return (pop16('sv16') + L('local e8:8 = zext(sv16) & 0xff;', 'local v:8 = (sext(%s) & 0xffffffff) | (e8 << 32);' % a, 'SignExt40(v);',
                              'SetAccAndFlag(%s, v);' % a))


@sig('pop', 'ArArpSttMod')
def _(c, ops):
    return pop16('sv16') + wr_reg(ops[0], 'sv16')


@sig('pop', 'Bx')
def _(c, ops):
    return pop16('sv16') + wr_reg(ops[0], 'sv16')


@sig('pop_prpage')
def _(c, ops):
    return pop16('sv16') + L('prpage = sv16;')


@sig('pop', 'Px')
def _(c, ops):
    p = ops[0]
    return (pop16('hi') + pop16('lo') + L('local v:4 = (zext(hi) << 16) | zext(lo);', '%s = v;' % p.reg,
                                          '%s = v[31,1];' % ('P0E' if p.reg == 'p0' else 'P1E')))


for _n, _r in (('pop_r6', 'r6'), ('pop_repc', 'repc'), ('pop_x0', 'x0'), ('pop_x1', 'x1'), ('pop_y1', 'y1')):
    @sig(_n)
    def _(c, ops, _r=_r):
        return pop16('sv16') + L('%s = sv16;' % _r)


@sig('popa', 'Ab')
def _(c, ops):
    return pop16('hi') + pop16('lo') + L('local w:4 = (zext(hi) << 16) | zext(lo);', 'local v:8 = sext(w);', 'SetAccAndFlag(%s, v);' % full(ops[0]))


# ---------------------------------------------------------------------------------------------------
# flow
# ---------------------------------------------------------------------------------------------------
def pushpc():
    return L('local pcv:4 = inst_next;', 'pcv = pcv >> 1;', 'local lo:2 = pcv:2;', 'local hi4:4 = pcv >> 16;', 'local hi:2 = hi4:2;',
             'if (CPC == 0) goto <cpc0>;', 'sp = sp - 1;', '*[DATA]:2 sp = hi;', 'sp = sp - 1;', '*[DATA]:2 sp = lo;', 'goto <pushed>;',
             '<cpc0>', 'sp = sp - 1;', '*[DATA]:2 sp = lo;', 'sp = sp - 1;', '*[DATA]:2 sp = hi;', '<pushed>')


def poppc():
    return L('local lo:2 = 0;', 'local hi:2 = 0;', 'if (CPC == 0) goto <cpc0>;', 'lo = *[DATA]:2 sp;', 'sp = sp + 1;', 'hi = *[DATA]:2 sp;',
             'sp = sp + 1;', 'goto <popped>;', '<cpc0>', 'hi = *[DATA]:2 sp;', 'sp = sp + 1;', 'lo = *[DATA]:2 sp;', 'sp = sp + 1;', '<popped>',
             'local tgt:3 = ((zext(hi) << 16) | zext(lo)) & 0x3ffff;')


def cond_skip(cond):
    if cond.cond is None:
        return ''
    return L('if (!%s) goto inst_next;' % cond.cond)


@sig('br', 'Address18_16', 'Address18_2', 'Cond')
def _(c, ops):
    a, hi, cd = ops
    return cond_skip(cd) + L('goto %s;' % a.target)


@sig('brr', 'RelAddr7', 'Cond')
def _(c, ops):
    r, cd = ops
    return cond_skip(cd) + L('goto %s;' % r.target)


@sig('call', 'Address18_16', 'Address18_2', 'Cond')
def _(c, ops):
    a, hi, cd = ops
    return cond_skip(cd) + pushpc() + L('call %s;' % a.target)


@sig('callr', 'RelAddr7', 'Cond')
def _(c, ops):
    r, cd = ops
    return cond_skip(cd) + pushpc() + L('call %s;' % r.target)


@sig('calla', 'Axl')
def _(c, ops):
    return L('local t16:2 = %s;' % ops[0].reg) + pushpc() + L('local tgt:3 = zext(t16);', 'call [tgt];') if False else \
        L('local t16:2 = %s[0,16];' % full(ops[0])) + pushpc() + L('local tgt:3 = zext(t16);', 'call [tgt];')


@sig('calla', 'Ax')
def _(c, ops):
    return L('local v:8 = sext(%s);' % full(ops[0]), 'local tgt:3 = v:3;', 'tgt = tgt & 0x3ffff;') + pushpc() + L('call [tgt];')


@sig('ret', 'Cond')
def _(c, ops):
    return cond_skip(ops[0]) + poppc() + L('return [tgt];')


@sig('reti', 'Cond')
def _(c, ops):
    return cond_skip(ops[0]) + poppc() + L('IE = 1;', 'return [tgt];')


@sig('rets', 'Imm8')
def _(c, ops):
    return poppc() + L('sp = sp + %s;' % ops[0].imm, 'return [tgt];')


@sig('dint')
def _(c, ops):
    return L('IE = 0;')


@sig('eint')
def _(c, ops):
    return L('IE = 1;')


@sig('load_ps', 'Imm2')
def _(c, ops):
    return L('PS0 = %s;' % ops[0].imm)


@sig('load_ps01', 'Imm4')
def _(c, ops):
    return L('local v:1 = %s;' % ops[0].imm, 'PS0 = v & 3;', 'PS1 = v >> 2;')


@sig('load_stepi', 'Imm7s')
def _(c, ops):
    return L('local v:2 = %s;' % ops[0].imm, 'cfgi = (cfgi & 0xff80) | (v & 0x7f);')


@sig('load_stepj', 'Imm7s')
def _(c, ops):
    return L('local v:2 = %s;' % ops[0].imm, 'cfgj = (cfgj & 0xff80) | (v & 0x7f);')


@sig('load_modi', 'Imm9')
def _(c, ops):
    return L('local v:2 = %s;' % ops[0].imm, 'cfgi = (cfgi & 0x7f) | (v << 7);')


@sig('load_modj', 'Imm9')
def _(c, ops):
    return L('local v:2 = %s;' % ops[0].imm, 'cfgj = (cfgj & 0x7f) | (v << 7);')


@sig('load_page', 'Imm8')
def _(c, ops):
    return L('PAGE = %s;' % ops[0].imm)


@sig('load_movpd', 'Imm2')
def _(c, ops):
    return L('PCMHI = %s;' % ops[0].imm)


@sig('break_')
def _(c, ops):
    return L('BCN = BCN - 1;', 'LP = (BCN != 0);')


# ---------------------------------------------------------------------------------------------------
# bit tests, shifts
# ---------------------------------------------------------------------------------------------------
@sig('tstb', 'MemImm8', 'Imm4')
def _(c, ops):
    m, b = ops
    return L('local v:2 = %s;' % loc(m), 'local bt:2 = %s;' % b.imm, 'v = v >> bt;', 'Z = v[0,1];')


@sig('tstb', 'RnStep', 'Imm4')
def _(c, ops):
    m, b = ops
    return L('local v:2 = %s;' % loc(m), 'local bt:2 = %s;' % b.imm, 'v = v >> bt;', 'Z = v[0,1];')


@sig('tstb', 'Register', 'Imm4')
def _(c, ops):
    r, b = ops
    return src16(r, False, 'sv16') + L('local bt:2 = %s;' % b.imm, 'sv16 = sv16 >> bt;', 'Z = sv16[0,1];')


@sig('tstb_r6', 'Imm4')
def _(c, ops):
    return L('local v:2 = r6;', 'local bt:2 = %s;' % ops[0].imm, 'v = v >> bt;', 'Z = v[0,1];')


@sig('tstb', 'SttMod', 'Imm16')
def _(c, ops):
    r, b = ops
    return src16(r, False, 'sv16') + L('local bt:2 = %s;' % b.imm, 'bt = bt & 0xf;', 'sv16 = sv16 >> bt;', 'Z = sv16[0,1];')


@sig('movs', 'MemImm8', 'Ab')
def _(c, ops):
    m, b = ops
    return L('local v:8 = sext(%s);' % loc(m), 'ShiftBus40(%s, v, sv);' % full(b))


@sig('movs', 'RnStep', 'Ab')
def _(c, ops):
    m, b = ops
    return L('local v:8 = sext(%s);' % loc(m), 'ShiftBus40(%s, v, sv);' % full(b))


@sig('movs', 'Register', 'Ab')
def _(c, ops):
    r, b = ops
    return src16(r, False, 'sv16') + L('local v:8 = sext(sv16);', 'ShiftBus40(%s, v, sv);' % full(b))


@sig('movs_r6_to', 'Ax')
def _(c, ops):
    return L('local v:8 = sext(r6);', 'ShiftBus40(%s, v, sv);' % full(ops[0]))


@sig('movsi', 'RnOld', 'Ab', 'Imm5s')
def _(c, ops):
    a, b, s = ops
    return L('local v:8 = sext(%s);' % a.reg, 'local shv:2 = %s;' % s.imm, 'ShiftBus40(%s, v, shv);' % full(b))


@sig('shfc', 'Ab', 'Ab', 'Cond')
def _(c, ops):
    a, b, cd = ops
    return cond_skip(cd) + L('local v:8 = sext(%s);' % full(a), 'ShiftBus40(%s, v, sv);' % full(b))


@sig('shfi', 'Ab', 'Ab', 'Imm6s')
def _(c, ops):
    a, b, s = ops
    return L('local v:8 = sext(%s);' % full(a), 'local shv:2 = %s;' % s.imm, 'ShiftBus40(%s, v, shv);' % full(b))


@sig('norm', 'Ax', 'RnStep')
def _(c, ops):
    a, m = ops
    m.pat.append(m.unitf)
    acc = full(a)
    m.build = []
    return L('if (N != 0) goto inst_next;', 'build %s;' % m.disp, 'local v:8 = sext(%s);' % acc, 'local v39:8 = (v << 25) s>> 25;', 'V = (v != v39);', 'VL = VL | V;',
             'v = v << 1;', 'C = v[40,1];', 'SignExt40(v);', 'SetAccAndFlag(%s, v);' % acc, 'local u:1 = %s;' % m.unitf,
             'local rv:2 = 0;', 'RGet(rv, u);', 'R = (rv == 0);')


@sig('exp', 'Bx')
def _(c, ops):
    return L('local v:8 = sext(%s);' % full(ops[0]), 'Exp40(sv, v);')


def exp_store(b):
    return L('local es:8 = sext(sv);', '%s = es:5;' % full(b))


@sig('exp', 'Bx', 'Ax')
def _(c, ops):
    a, b = ops
    return L('local v:8 = sext(%s);' % full(a), 'Exp40(sv, v);') + exp_store(b)


def exp_mem(m):
    return L('local mv:4 = zext(%s) << 16;' % loc(m), 'local v:8 = sext(mv);', 'Exp40(sv, v);')


@sig('exp', 'RnStep')
def _(c, ops):
    return exp_mem(ops[0])


@sig('exp', 'RnStep', 'Ax')
def _(c, ops):
    return exp_mem(ops[0]) + exp_store(ops[1])


def exp_reg(r):
    nm = getattr(r, 'enumname', None)
    if nm in ('a0', 'a1'):
        return L('local v:8 = sext(%s);' % nm, 'Exp40(sv, v);')
    return src16(r, False, 'sv16') + L('local mv:4 = zext(sv16) << 16;', 'local v:8 = sext(mv);', 'Exp40(sv, v);')


@sig('exp', 'Register')
def _(c, ops):
    return exp_reg(ops[0])


@sig('exp', 'Register', 'Ax')
def _(c, ops):
    return exp_reg(ops[0]) + exp_store(ops[1])


REGSPLIT[(0x9440, 0)] = [24, 25]
REGSPLIT[(0x9040, 0)] = [24, 25]


@sig('exp_r6')
def _(c, ops):
    return L('local mv:4 = zext(r6) << 16;', 'local v:8 = sext(mv);', 'Exp40(sv, v);')


@sig('exp_r6', 'Ax')
def _(c, ops):
    return L('local mv:4 = zext(r6) << 16;', 'local v:8 = sext(mv);', 'Exp40(sv, v);') + exp_store(ops[0])


@sig('movr', 'ArMem', 'Abh')
def _(c, ops):
    m, b = ops
    return ar_addrs(m) + L('local mv:4 = zext(*[DATA]:2 ap1) << 16;', 'local v:8 = sext(mv);', 'local k:8 = 0x8000;', 'local r:8 = 0;',
                           'AddAcc(r, v, k);', 'SatAndSetAccAndFlag(%s, r);' % full(b))


def movr16(src_stmt, b):
    return src_stmt + L('local r32:4 = zext(sv16) + 0x8000;', 'C = r32[16,1];', 'V = 0;', 'local r:8 = zext(r32 & 0xffff);',
                        'SatAndSetAccAndFlag(%s, r);' % full(b))


@sig('movr', 'RnStep', 'Ax')
def _(c, ops):
    return movr16(L('local sv16:2 = %s;' % loc(ops[0])), ops[1])


@sig('movr', 'Register', 'Ax')
def _(c, ops):
    r, b = ops
    nm = getattr(r, 'enumname', None)
    if nm in ('a0', 'a1'):
        return L('local v:8 = sext(%s);' % nm, 'local k:8 = 0x8000;', 'local r:8 = 0;', 'AddAcc(r, v, k);', 'SatAndSetAccAndFlag(%s, r);' % full(b))
    if nm == 'p0h':
        return L('local v:8 = 0;', 'P40_0(v);', 'local k:8 = 0x8000;', 'local r:8 = 0;', 'AddAcc(r, v, k);', 'SatAndSetAccAndFlag(%s, r);' % full(b))
    return movr16(src16(r, False, 'sv16'), b)


REGSPLIT[(0x9CC0, 0)] = [11, 24, 25]


@sig('movr', 'Bx', 'Ax')
def _(c, ops):
    a, b = ops
    return L('local v:8 = sext(%s);' % full(a), 'local k:8 = 0x8000;', 'local r:8 = 0;', 'AddAcc(r, v, k);', 'SatAndSetAccAndFlag(%s, r);' % full(b))


@sig('movr_r6_to', 'Ax')
def _(c, ops):
    return movr16(L('local sv16:2 = r6;'), ops[0])


# ---------------------------------------------------------------------------------------------------
# multiplier, product sums
# ---------------------------------------------------------------------------------------------------
def sgn(n):
    return n[0] == 'S'


def product_sum(base, acc, sub0, al0, sub1, al1):
    t = '    local va:8 = 0;\n    P40_0(va);\n    local vb:8 = 0;\n    P40_1(vb);\n'
    if al0:
        t += '    va = ((va >> 16) << 40) s>> 40;\n'
    if al1:
        t += '    vb = ((vb >> 16) << 40) s>> 40;\n'
    if base == 'BZr':
        t += '    local vc:8 = 0;\n'
    elif base == 'BAc':
        t += '    local vc:8 = sext(%s);\n' % acc
    else:
        t += '    local svw:4 = zext(sv) << 16;\n    local vc:8 = sext(svw);\n'
        if base == 'BSr':
            t += '    vc = vc | 0x8000;\n'
    t += '    local psa:8 = 0;\n    %s(psa, vc, va);\n    local tc:1 = C;\n    local tv:1 = V;\n' % ('SubAcc' if sub0 else 'AddAcc')
    t += '    local psb:8 = 0;\n    %s(psb, psa, vb);\n' % ('SubAcc' if sub1 else 'AddAcc')
    if sub0 == sub1:
        t += '    C = C | tc;\n    V = V | tv;\n'
    else:
        t += '    C = C ^ tc;\n    V = V ^ tv;\n'
    t += '    SatAndSetAccAndFlag(%s, psb);\n' % acc
    return t


def parse_cn(ops):
    cn = [o.val for o in ops if o.typ == 'Cn' and o.val not in ('EMod', 'DMod')]
    return cn


def ps_from_cn(cn, acc):
    # [x0s, y0s, x1s, y1s, base, sub0, al0, sub1, al1]
    return product_sum(cn[4], acc, cn[5] == 'Sub', cn[6] == 'PA', cn[7] == 'Sub', cn[8] == 'PA')


def muls_from_cn(cn):
    return mul_text(0, cn[0][0] == 'S', cn[1][0] == 'S') + mul_text(1, cn[2][0] == 'S', cn[3][0] == 'S')


def acc_named(ops):
    for o in ops:
        if o.typ in ('At', 'AtNamed', 'Const') and o.kind in ('Ax', 'Bx', 'Ab'):
            return full(o)
    raise Exception('no accumulator')


SWAPX = '    local sx:2 = x0;\n    x0 = x1;\n    x1 = sx;\n'


@sig('mma', 'Ax', *['Cn'] * 9)
@sig('mma', 'Bx', *['Cn'] * 9)
@sig('mma', 'Ab', *['Cn'] * 9)
def _(c, ops):
    cn = parse_cn(ops)
    acc = full(ops[0])
    return ps_from_cn(cn, acc) + SWAPX + muls_from_cn(cn)


def arp_locals(m):
    return ('    local pk:8 = %s;\n    local ia:2 = pk:2;\n    local pk1:8 = pk >> 16;\n    local ioa:2 = pk1:2;\n'
            '    local pk2:8 = pk >> 32;\n    local ja:2 = pk2:2;\n    local pk3:8 = pk >> 48;\n    local joa:2 = pk3:2;\n' % m.disp)


for _a in ('Ax', 'Bx', 'Ab'):
    @sig('mma', 'ArpMem', 'Cn', 'Cn', _a, *['Cn'] * 9)
    def _(c, ops):
        m = ops[0]
        cn = parse_cn(ops)
        acc = acc_named(ops)
        return (ps_from_cn(cn, acc) + arp_locals(m) + L('x0 = *[DATA]:2 ia;', 'y0 = *[DATA]:2 ja;', 'x1 = *[DATA]:2 ioa;', 'y1 = *[DATA]:2 joa;') +
                muls_from_cn(cn))

    @sig('mma_mx_xy', 'ArMem', _a, *['Cn'] * 9)
    def _(c, ops):
        m = ops[0]
        cn = parse_cn(ops)
        return ps_from_cn(cn, full(ops[1])) + SWAPX + ar_addrs(m) + L('y0 = *[DATA]:2 ap1;') + muls_from_cn(cn)

    @sig('mma_xy_mx', 'ArMem', _a, *['Cn'] * 9)
    def _(c, ops):
        m = ops[0]
        cn = parse_cn(ops)
        return ps_from_cn(cn, full(ops[1])) + SWAPX + ar_addrs(m) + L('y1 = *[DATA]:2 ap1;') + muls_from_cn(cn)

    @sig('mma_my_my', 'ArMem', _a, *['Cn'] * 9)
    def _(c, ops):
        m = ops[0]
        cn = parse_cn(ops)
        return ps_from_cn(cn, full(ops[1])) + ar_addrs(m) + L('x0 = *[DATA]:2 ap1;', 'x1 = *[DATA]:2 ap2;') + muls_from_cn(cn)

    @sig('app', _a, *['Cn'] * 5)
    def _(c, ops):
        cn = parse_cn(ops)
        return product_sum(cn[0], full(ops[0]), cn[1] == 'Sub', cn[2] == 'PA', cn[3] == 'Sub', cn[4] == 'PA')


EXPAND['mma_mov'] = ('Ab', 'Ax')


@sig('mma_mov', 'Axh', 'Bxh', 'ArMem', 'Ab', *['Cn'] * 9)
@sig('mma_mov', 'Axh', 'Bxh', 'ArMem', 'Ax', *['Cn'] * 9)
def _(c, ops):
    u, v, m, a = ops[:4]
    cn = parse_cn(ops)
    return (ar_addrs(m) + L('local uv:8 = 0;', 'GetSatAccNoFlag(uv, %s);' % full(u), 'local vv:8 = 0;', 'GetSatAccNoFlag(vv, %s);' % full(v),
                            'local uh:8 = uv >> 16;', 'local vh:8 = vv >> 16;', '*[DATA]:2 ap2 = vh:2;', '*[DATA]:2 ap1 = uh:2;') +
            ps_from_cn(cn, full(a)) + SWAPX + muls_from_cn(cn))


@sig('mma_mov', 'ArMem', 'Ax', *['Cn'] * 9)
def _(c, ops):
    m, a = ops[:2]
    cn = parse_cn(ops)
    other = 'a1' if full(a) == 'a0' else 'a0'
    return (ar_addrs(m) + L('local uv:8 = 0;', 'GetSatAccNoFlag(uv, %s);' % full(a), 'local vv:8 = 0;', 'GetSatAccNoFlag(vv, %s);' % other,
                            'local uh:8 = uv >> 16;', 'local vh:8 = vv >> 16;', '*[DATA]:2 ap2 = vh:2;', '*[DATA]:2 ap1 = uh:2;') +
            ps_from_cn(cn, full(a)) + SWAPX + muls_from_cn(cn))


EXPAND['mma_mov'] = ('Ax',)
EXPAND['max_ge'] = EXPAND['max_gt'] = EXPAND['min_le'] = EXPAND['min_lt'] = ('Ax',)
EXPAND['max_ge_r0'] = EXPAND['max_gt_r0'] = EXPAND['min_le_r0'] = EXPAND['min_lt_r0'] = ('Ax',)


@sig('mov_sv_app', 'ArMem', 'Bx', *['Cn'] * 5)
@sig('mov_sv_app', 'ArMem', *['Cn'] * 5)
def _(c, ops):
    m = ops[0]
    b = ops[1] if ops[1].typ != 'Cn' else None
    cn = parse_cn(ops)
    if b is None:
        raise Exception('mov_sv_app: accumulator constant missing')
    return ar_addrs(m) + L('sv = *[DATA]:2 ap1;') + product_sum(cn[0], full(b), cn[1] == 'Sub', cn[2] == 'PA', cn[3] == 'Sub', cn[4] == 'PA')


def mulgen(op, a, mem_stmts):
    """MulGeneric: mem_stmts sets x0 / y0 first"""
    acc = full(a)
    n = op
    t = mem_stmts
    if n not in ('mpy', 'mpysu'):
        t += L('local v:8 = sext(%s);' % acc, 'local pr:8 = 0;', 'P40_0(pr);')
        if n in ('maa', 'maasu'):
            t += L('pr = ((pr >> 16) << 40) s>> 40;')
        t += L('local r:8 = 0;', 'AddAcc(r, v, pr);', 'SatAndSetAccAndFlag(%s, r);' % acc)
    xs, ys = {'mpy': (True, True), 'mac': (True, True), 'maa': (True, True), 'mpysu': (False, True), 'macsu': (False, True),
              'maasu': (False, True), 'macus': (True, False), 'macuu': (False, False)}[n]
    return t + mul_text(0, xs, ys)


@sig('mul', 'Mul3', 'RnStep', 'Imm16', 'Ax')
def _(c, ops):
    op, y, x, a = ops
    return mulgen(op.enumname, a, L('y0 = %s;' % loc(y), 'x0 = %s;' % x.imm))


@sig('mul_y0', 'Mul3', 'RnStep', 'Ax')
def _(c, ops):
    op, x, a = ops
    return mulgen(op.enumname, a, L('x0 = %s;' % loc(x)))


@sig('mul_y0', 'Mul3', 'Register', 'Ax')
def _(c, ops):
    op, x, a = ops
    return mulgen(op.enumname, a, src16(x, False, 'sv16') + L('x0 = sv16;'))


@sig('mul', 'Mul3', 'RnStep', 'RnStep', 'Ax')
def _(c, ops):
    op, y, x, a = ops
    return mulgen(op.enumname, a, L('local yv:2 = %s;' % loc(y), 'local xv:2 = %s;' % loc(x), 'y0 = yv;', 'x0 = xv;'))


@sig('mul_y0_r6', 'Mul3', 'Ax')
def _(c, ops):
    op, a = ops
    return mulgen(op.enumname, a, L('x0 = r6;'))


@sig('mul_y0', 'Mul2', 'MemImm8', 'Ax')
def _(c, ops):
    op, x, a = ops
    return mulgen(op.enumname, a, L('x0 = %s;' % loc(x)))


@sig('mpyi', 'Imm8s')
def _(c, ops):
    return L('x0 = %s;' % ops[0].imm) + mul_text(0, True, True)


def msu_tail(a):
    acc = full(a)
    return L('local v:8 = sext(%s);' % acc, 'local pr:8 = 0;', 'P40_0(pr);', 'local r:8 = 0;', 'SubAcc(r, v, pr);', 'SatAndSetAccAndFlag(%s, r);' % acc)


@sig('msu', 'RnStep', 'RnStep', 'Ax')
def _(c, ops):
    y, x, a = ops
    return L('local yi:2 = 0;') and (L('local yv:2 = %s;' % loc(y), 'local xv:2 = %s;' % loc(x)) + msu_tail(a) + L('y0 = yv;', 'x0 = xv;') + mul_text(0, True, True))


@sig('msu', 'RnStep', 'Imm16', 'Ax')
def _(c, ops):
    y, x, a = ops
    return L('local yv:2 = %s;' % loc(y)) + msu_tail(a) + L('y0 = yv;', 'x0 = %s;' % x.imm) + mul_text(0, True, True)


@sig('msusu', 'ArMem', 'Ax')
def _(c, ops):
    m, a = ops
    return ar_addrs(m) + L('local xv:2 = *[DATA]:2 ap1;') + msu_tail(a) + L('x0 = xv;') + mul_text(0, False, True)


@sig('mac_x1to0', 'Ax')
def _(c, ops):
    a = ops[0]
    acc = full(a)
    return (L('local v:8 = sext(%s);' % acc, 'local pr:8 = 0;', 'P40_0(pr);', 'local r:8 = 0;', 'AddAcc(r, v, pr);', 'SatAndSetAccAndFlag(%s, r);' % acc,
              'x0 = x1;') + mul_text(0, True, True))


@sig('mac1', 'ArpMem', 'Ax')
def _(c, ops):
    m, a = ops
    acc = full(a)
    return (arp_locals(m) + L('local v:8 = sext(%s);' % acc, 'local pr:8 = 0;', 'P40_1(pr);', 'local r:8 = 0;', 'AddAcc(r, v, pr);',
                              'SatAndSetAccAndFlag(%s, r);' % acc, 'x1 = *[DATA]:2 ia;', 'y1 = *[DATA]:2 ja;') + mul_text(1, True, True))


@sig('sqr_sqr_add3', 'Ab', 'Ab')
def _(c, ops):
    a, b = ops
    return (L('local value:8 = sext(%s);' % full(a)) + product_sum('BAc', full(b), False, False, False, False) +
            L('local vh:8 = value >> 16;', 'x0 = vh:2;', 'y0 = x0;', 'x1 = value:2;', 'y1 = x1;') + mul_text(0, True, True) + mul_text(1, True, True))


@sig('sqr_sqr_add3', 'ArMem', 'Ab')
def _(c, ops):
    m, b = ops
    return (ar_addrs(m) + product_sum('BAc', full(b), False, False, False, False) +
            L('x0 = *[DATA]:2 ap1;', 'y0 = x0;', 'x1 = *[DATA]:2 ap2;', 'y1 = x1;') + mul_text(0, True, True) + mul_text(1, True, True))


@sig('sqr_mpysu_add3a', 'Ab', 'Ab')
def _(c, ops):
    a, b = ops
    return (L('local value:8 = sext(%s);' % full(a)) + product_sum('BAc', full(b), False, False, False, True) +
            L('local vh:8 = value >> 16;', 'x0 = vh:2;', 'y0 = x0;', 'y1 = x0;', 'x1 = value:2;') + mul_text(0, True, True) + mul_text(1, False, True))


@sig('clrp0')
def _(c, ops):
    return L('p0 = 0;', 'P0E = 0;')


@sig('clrp1')
def _(c, ops):
    return L('p1 = 0;', 'P1E = 0;')


@sig('clrp')
def _(c, ops):
    return L('p0 = 0;', 'P0E = 0;', 'p1 = 0;', 'P1E = 0;')


@sig('addhp', 'ArMem', 'Px', 'Ax')
def _(c, ops):
    m, p, a = ops
    return (ar_addrs(m) + L('local mv:4 = (zext(*[DATA]:2 ap1) << 16) | 0x8000;', 'local v:8 = sext(mv);', 'local pr:8 = 0;', '%s(pr);' % p40(p),
                            'local r:8 = 0;', 'AddAcc(r, v, pr);', 'SatAndSetAccAndFlag(%s, r);' % full(a)))


# ---------------------------------------------------------------------------------------------------
# address register operations
# ---------------------------------------------------------------------------------------------------
FIXSTEP = {'modr_i2': (4, 0), 'modr_i2_dmod': (4, 1), 'modr_d2': (5, 0), 'modr_d2_dmod': (5, 1)}


@sig('modr', 'RnStep')
@sig('modr_dmod', 'RnStep')
def _(c, ops):
    m = ops[0]
    m.pat.append(m.unitf)
    return L('local u:1 = %s;' % m.unitf, 'local rv:2 = 0;', 'RGet(rv, u);', 'R = (rv == 0);')


for _n in FIXSTEP:
    @sig(_n, 'Rn')
    def _(c, ops):
        m = ops[0]
        m.pat.append(m.unitf)
        return L('local u:1 = %s;' % m.unitf, 'local rv:2 = 0;', 'RGet(rv, u);', 'R = (rv == 0);')


for _n in ('modr_eemod', 'modr_edmod', 'modr_demod', 'modr_ddmod'):
    @sig(_n, 'ArpMem')
    def _(c, ops):
        return ''


EXPAND['bitrev'] = EXPAND['bitrev_dbrv'] = EXPAND['bitrev_ebrv'] = ('Rn',)


@sig('bitrev', 'Rn')
@sig('bitrev_dbrv', 'Rn')
@sig('bitrev_ebrv', 'Rn')
def _(c, ops):
    n = int(ops[0].reg[1:])
    t = L('local rv:2 = 0;', 'BitRev16(rv, %s);' % ops[0].reg, '%s = rv;' % ops[0].reg)
    if c.name == 'bitrev_dbrv':
        t += L('mod2 = mod2 & 0x%x;' % (~(1 << (8 + n)) & 0xffff))
    elif c.name == 'bitrev_ebrv':
        t += L('mod2 = mod2 | 0x%x;' % (1 << (8 + n)))
    return t


def swap2(a, b, tmp='sw'):
    return L('%s = %s;' % (tmp, a), '%s = %s;' % (a, b), '%s = %s;' % (b, tmp))


@sig('banke', 'BankFlags')
def _(c, ops):
    f = ops[0].imm
    t = L('local f:1 = %s;' % f, 'local sw:2 = 0;')
    for bit, pairs in ((1, [('cfgi', 'cfgib')]), (2, [('r4', 'r4b')]), (4, [('r1', 'r1b')]), (8, [('r0', 'r0b')]), (16, [('r7', 'r7b')]), (32, [('cfgj', 'cfgjb')])):
        t += L('if ((f & %d) == 0) goto <bk%d>;' % (bit, bit))
        for a, b in pairs:
            t += swap2(a, b)
        if bit == 1:
            t += L('if (STP16 == 0) goto <bk%d>;' % bit) + swap2('stepi0', 'stepi0b')
        if bit == 32:
            t += L('if (STP16 == 0) goto <bk%d>;' % bit) + swap2('stepj0', 'stepj0b')
        t += L('<bk%d>' % bit)
    return t


EXPAND['bankr'] = ('Ar', 'Arp')


@sig('bankr')
def _(c, ops):
    t = L('local sw:2 = 0;')
    for r in ('ar0', 'ar1', 'arp0', 'arp1', 'arp2', 'arp3'):
        t += swap2(r, r + 'b')
    return t


@sig('bankr', 'Ar')
@sig('bankr', 'Arp')
def _(c, ops):
    return L('local sw:2 = 0;') + swap2(ops[0].reg, ops[0].reg + 'b')


@sig('bankr', 'Ar', 'Arp')
def _(c, ops):
    return L('local sw:2 = 0;') + swap2(ops[0].reg, ops[0].reg + 'b') + swap2(ops[1].reg, ops[1].reg + 'b')


FLAG_SH = ['LM', 'VL', 'E', 'C', 'C1', 'V', 'N', 'M', 'Z', 'R']
SWAP_SH = ['PCMHI', 'SAT', 'SATA', 'HWM', 'S', 'PS0', 'PS1', 'PAGE', 'STP16', 'CMD', 'IM0', 'IM1', 'IM2', 'IMV', 'EPI', 'EPJ']


def ctx_swap():
    t = L('local sb:1 = 0;', 'local sw:2 = 0;')
    for r in SWAP_SH:
        t += L('sb = %s;' % r, '%s = SW_%s;' % (r, r), 'SW_%s = sb;' % r)
    t += swap2('mod2', 'mod2s')
    for r in ('ar0', 'ar1', 'arp0', 'arp1', 'arp2', 'arp3'):
        t += swap2(r, r + 'b')
    return t


def ctx_store():
    t = ''.join(L('SH_%s = %s;' % (r, r)) for r in FLAG_SH) + ctx_swap()
    t += L('if (CREP != 0) goto <crep>;', 'repcs = repc;', '<crep>',
           'if (CCNTA != 0) goto <ccnta>;', 'a1s = a1;', 'b1s = b1;', 'goto <cdone>;', '<ccnta>',
           'local oa:8 = sext(a1);', 'local ob:8 = sext(b1);', 'b1 = oa:5;', 'SetAccAndFlag(a1, ob);', '<cdone>')
    return t


def ctx_restore():
    t = ''.join(L('%s = SH_%s;' % (r, r)) for r in FLAG_SH) + ctx_swap()
    t += L('if (CREP != 0) goto <crep>;', 'repc = repcs;', '<crep>',
           'if (CCNTA != 0) goto <ccnta>;', 'a1 = a1s;', 'b1 = b1s;', 'goto <cdone>;', '<ccnta>',
           'local ta:5 = a1;', 'a1 = b1;', 'b1 = ta;', '<cdone>')
    return t


@sig('cntx_s')
def _(c, ops):
    return ctx_store()


@sig('cntx_r')
def _(c, ops):
    return ctx_restore()


@sig('retic', 'Cond')
def _(c, ops):
    return cond_skip(ops[0]) + poppc() + L('IE = 1;') + ctx_restore() + L('return [tgt];')


@sig('retd')
@sig('retid')
@sig('retidc')
def _(c, ops):
    return poppc() + L('return [tgt];')


@sig('trap')
def _(c, ops):
    return L('teak_trap();')


@sig('vtrclr0')
def _(c, ops):
    return L('vtr0 = 0;')


@sig('vtrclr1')
def _(c, ops):
    return L('vtr1 = 0;')


@sig('vtrclr')
def _(c, ops):
    return L('vtr0 = 0;', 'vtr1 = 0;')


def vtr_set(a, v):
    return L('local v:8 = zext(%s);' % v, 'SatAndSetAccAndFlag(%s, v);' % full(a))


@sig('vtrmov0', 'Axl')
def _(c, ops):
    return vtr_set(ops[0], 'vtr0')


@sig('vtrmov1', 'Axl')
def _(c, ops):
    return vtr_set(ops[0], 'vtr1')


@sig('vtrmov', 'Axl')
def _(c, ops):
    return L('local w:2 = (vtr1 & 0xff00) | (vtr0 >> 8);') + vtr_set(ops[0], 'w')


@sig('vtrshr')
def _(c, ops):
    return L('vtr0 = (vtr0 >> 1) | (zext(C) << 15);', 'vtr1 = (vtr1 >> 1) | (zext(C1) << 15);')


# ---------------------------------------------------------------------------------------------------
# min / max
# ---------------------------------------------------------------------------------------------------
def other_acc(a):
    return 'a1' if full(a) == 'a0' else 'a0'


def minmax(c, ops, r0mem):
    a, m = ops
    acc = full(a)
    cond = {'max_ge': 'neg == 0', 'max_gt': '(neg == 0) && (d != 0)', 'min_le': '(neg != 0) || (d == 0)', 'min_lt': 'neg != 0'}[c.name.replace('_r0', '')]
    m.build = []
    t = L('local u:8 = sext(%s);' % acc)
    if r0mem:
        t += L('local r0o:2 = r0;', 'build %s;' % m.disp, 'local v:8 = sext(%s);' % loc(m))
    else:
        t += L('local v:8 = sext(%s);' % other_acc(a), 'local r0o:2 = r0;', 'build %s;' % m.disp)
    t += L('local d:8 = v - u;', 'local neg:1 = (d s< 0);', 'if (%s) goto <yes>;' % cond, 'M = 0;', 'goto <end>;', '<yes>', 'M = 1;', 'mixp = r0o;',
           '%s = v:5;' % acc, '<end>')
    return t


for _n in ('max_ge', 'max_gt', 'min_le', 'min_lt'):
    @sig(_n, 'Ax', 'StepZIDS')
    def _(c, ops):
        return minmax(c, ops, False)

    @sig(_n + '_r0', 'Ax', 'StepZIDS')
    def _(c, ops):
        return minmax(c, ops, True)


def minmaxvtr(a, b, mn):
    ua, ub = full(a), full(b)
    sub = lambda x, y: ('%s - %s' % (x, y))
    wh = sub('uh', 'vh') if mn else sub('vh', 'uh')
    wl = sub('ul', 'vl') if mn else sub('vl', 'ul')
    return L('local u:8 = sext(%s);' % ua, 'local v:8 = sext(%s);' % ub,
             'local uh:8 = ((u >> 16) << 40) s>> 40;', 'local ul:8 = (u << 48) s>> 48;',
             'local vh:8 = ((v >> 16) << 40) s>> 40;', 'local vl:8 = (v << 48) s>> 48;',
             'local wh:8 = %s;' % wh, 'local wl:8 = %s;' % wl,
             'C = (wh s>= 0);', 'C1 = (wl s>= 0);',
             'if (C != 0) goto <h1>;', 'wh = uh;', 'goto <h2>;', '<h1>', 'wh = vh;', '<h2>',
             'if (C1 != 0) goto <l1>;', 'wl = ul;', 'goto <l2>;', '<l1>', 'wl = vl;', '<l2>',
             'local w:8 = (wh << 16) | (wl & 0xffff);', '%s = w:5;' % ua,
             'vtr0 = (vtr0 >> 1) | (zext(C) << 15);', 'vtr1 = (vtr1 >> 1) | (zext(C1) << 15);')


EXPAND['max2_vtr'] = EXPAND['min2_vtr'] = ('Ax', 'Bx')
for _n in ('max2_vtr', 'min2_vtr'):
    @sig(_n, 'Ax')
    def _(c, ops):
        a = ops[0]
        o = Op_like(other_acc(a))
        return minmaxvtr(a, o, c.name == 'min2_vtr')

    @sig(_n, 'Ax', 'Bx')
    def _(c, ops):
        return minmaxvtr(ops[0], ops[1], c.name == 'min2_vtr')


class Op_like:
    def __init__(self, reg):
        self.reg = reg


def counter(o):
    r = full(o)
    return {'a0': 'a1', 'a1': 'a0', 'b0': 'b1', 'b1': 'b0'}[r]


for _n in ('max2_vtr_movl', 'max2_vtr_movh', 'min2_vtr_movl', 'min2_vtr_movh'):
    EXPAND[_n] = ('Ax', 'Bx')

    @sig(_n, 'Ax', 'Bx', 'ArMem')
    @sig(_n, 'Bx', 'Ax', 'ArMem')
    def _(c, ops):
        a, b, m = ops
        mn = c.name.startswith('min')
        t = ar_addrs(m) + minmaxvtr(a, b, mn)
        t += L('local cv:8 = 0;', 'GetSatAccNoFlag(cv, %s);' % counter(a))
        if c.name.endswith('h'):
            t += L('cv = cv >> 16;')
        return t + L('*[DATA]:2 ap1 = cv:2;')


for _n in ('max2_vtr_movij', 'max2_vtr_movji', 'min2_vtr_movij', 'min2_vtr_movji'):
    EXPAND[_n] = ('Ax', 'Bx')

    @sig(_n, 'Ax', 'Bx', 'ArpMem')
    def _(c, ops):
        a, b, m = ops
        mn = c.name.startswith('min')
        t = arp_locals(m) + minmaxvtr(a, b, mn)
        t += L('local cv:8 = 0;', 'GetSatAccNoFlag(cv, %s);' % counter(a), 'local ch:8 = cv >> 16;')
        if c.name.endswith('ij'):
            t += L('*[DATA]:2 ia = ch:2;', '*[DATA]:2 ja = cv:2;')
        else:
            t += L('*[DATA]:2 ia = cv:2;', '*[DATA]:2 ja = ch:2;')
        return t


# ---------------------------------------------------------------------------------------------------
# paired accumulator operations
# ---------------------------------------------------------------------------------------------------
def pair_result(hi_op, lo_op, hi_a, hi_b, lo_a, lo_b):
    """high = sext(hi_a) hi_op sext(hi_b); low = lo_a lo_op lo_b (16 bit); result:8 = (high<<16)|low"""
    return L('local hv:8 = sext(%s) %s sext(%s);' % (hi_a, hi_op, hi_b), 'local lv:2 = %s %s %s;' % (lo_a, lo_op, lo_b),
             'local res:8 = (hv << 16) | zext(lv);')


for _n, (_h, _l) in (('add_add', ('+', '+')), ('add_sub', ('+', '-')), ('sub_add', ('-', '+')), ('sub_sub', ('-', '-'))):
    @sig(_n, 'ArpMem', 'Ab')
    def _(c, ops, _h=_h, _l=_l):
        m, b = ops
        return (arp_locals(m) + L('local mj:2 = *[DATA]:2 ja;', 'local mi:2 = *[DATA]:2 ia;', 'local mjo:2 = *[DATA]:2 joa;', 'local mio:2 = *[DATA]:2 ioa;') +
                pair_result(_h, _l, 'mj', 'mi', 'mjo', 'mio') + L('%s = res:5;' % full(b)))


@sig('add_sub_sv', 'ArMem', 'Ab')
@sig('sub_add_sv', 'ArMem', 'Ab')
def _(c, ops):
    m, b = ops
    h, l = ('+', '-') if c.name == 'add_sub_sv' else ('-', '+')
    return (ar_addrs(m) + L('local m1:2 = *[DATA]:2 ap1;', 'local m2:2 = *[DATA]:2 ap2;') + pair_result(h, l, 'm1', 'sv', 'm2', 'sv') +
            L('%s = res:5;' % full(b)))


@sig('sub_add_i_mov_j_sv', 'ArpMem', 'Ab')
@sig('sub_add_j_mov_i_sv', 'ArpMem', 'Ab')
def _(c, ops):
    m, b = ops
    if c.name == 'sub_add_i_mov_j_sv':
        pa, po, qa = 'ia', 'ioa', 'ja'
    else:
        pa, po, qa = 'ja', 'joa', 'ia'
    return (arp_locals(m) + L('local m1:2 = *[DATA]:2 %s;' % pa, 'local m2:2 = *[DATA]:2 %s;' % po) + pair_result('-', '+', 'm1', 'sv', 'm2', 'sv') +
            L('%s = res:5;' % full(b), 'sv = *[DATA]:2 %s;' % qa))


@sig('add_sub_i_mov_j', 'ArpMem', 'Ab')
@sig('add_sub_j_mov_i', 'ArpMem', 'Ab')
def _(c, ops):
    m, b = ops
    if c.name == 'add_sub_i_mov_j':
        pa, po, qa = 'ia', 'ioa', 'ja'
    else:
        pa, po, qa = 'ja', 'joa', 'ia'
    return (arp_locals(m) + L('local m1:2 = *[DATA]:2 %s;' % pa, 'local m2:2 = *[DATA]:2 %s;' % po) + pair_result('+', '-', 'm1', 'sv', 'm2', 'sv') +
            L('local ex:8 = 0;', 'GetSatAccNoFlag(ex, %s);' % full(b), '%s = res:5;' % full(b), '*[DATA]:2 %s = ex:2;' % qa))


# mov2 family with ar / arp pairs
@sig('mov2_ax_mij', 'Ab', 'ArpMem')
@sig('mov2_ax_mji', 'Ab', 'ArpMem')
def _(c, ops):
    a, m = ops
    t = arp_locals(m) + L('local v:8 = 0;', 'GetSatAccNoFlag(v, %s);' % full(a), 'local vh:8 = v >> 16;')
    if c.name.endswith('mij'):
        return t + L('*[DATA]:2 ia = vh:2;', '*[DATA]:2 ja = v:2;')
    return t + L('*[DATA]:2 ja = vh:2;', '*[DATA]:2 ia = v:2;')


@sig('mov2_mij_ax', 'ArpMem', 'Ab')
@sig('mov2_mji_ax', 'ArpMem', 'Ab')
def _(c, ops):
    m, b = ops
    t = arp_locals(m)
    if c.name == 'mov2_mij_ax':
        t += L('local h:2 = *[DATA]:2 ia;', 'local l:2 = *[DATA]:2 ja;')
    else:
        t += L('local l:2 = *[DATA]:2 ia;', 'local h:2 = *[DATA]:2 ja;')
    return t + L('local w:4 = (zext(h) << 16) | zext(l);', 'local v:8 = sext(w);', '%s = v:5;' % full(b))


@sig('mov2_abh_m', 'Abh', 'Abh', 'ArMem')
def _(c, ops):
    ax, ay, m = ops
    return (ar_addrs(m) + L('local u:8 = 0;', 'GetSatAccNoFlag(u, %s);' % full(ax), 'local v:8 = 0;', 'GetSatAccNoFlag(v, %s);' % full(ay),
                            'local uh:8 = u >> 16;', 'local vh:8 = v >> 16;', '*[DATA]:2 ap2 = vh:2;', '*[DATA]:2 ap1 = uh:2;'))


@sig('mov2_axh_m_y0_m', 'Axh', 'ArMem')
def _(c, ops):
    a, m = ops
    return ar_addrs(m) + L('local u:8 = 0;', 'GetSatAccNoFlag(u, %s);' % full(a), 'local uh:8 = u >> 16;', '*[DATA]:2 ap2 = y0;', '*[DATA]:2 ap1 = uh:2;')


for _n in ('exchange_iaj', 'exchange_riaj', 'exchange_jai', 'exchange_rjai'):
    @sig(_n, 'Axh', 'ArpMem')
    def _(c, ops):
        a, m = ops
        acc = full(a)
        iaj = c.name in ('exchange_iaj', 'exchange_riaj')
        rnd = c.name in ('exchange_riaj', 'exchange_rjai')
        wa, ra = ('ja', 'ia') if iaj else ('ia', 'ja')
        t = arp_locals(m) + L('local u:8 = 0;', 'GetSatAccNoFlag(u, %s);' % acc, 'local uh:8 = u >> 16;', '*[DATA]:2 %s = uh:2;' % wa,
                              'local w:4 = zext(*[DATA]:2 %s) << 16;' % ra)
        if rnd:
            t += L('w = w | 0x8000;')
        return t + L('local v:8 = sext(w);', '%s = v:5;' % acc)


@sig('tst4b', 'ArMem')
def _(c, ops):
    m = ops[0]
    return ar_addrs(m) + L('local v:2 = *[DATA]:2 ap1;', 'local bt:2 = a0l & 0xf;', 'v = v >> bt;', 'Z = v[0,1];', 'C = Z;')


@sig('tst4b', 'ArMem', 'Ax')
def _(c, ops):
    m, cc = ops
    return (L('local va:8 = sext(a0);', 'local bt:2 = a0l & 0xf;', 'local sV:1 = V;', 'local sVL:1 = VL;', 'local sM:1 = M;', 'local sN:1 = N;', 'local sE:1 = E;',
              'ShiftBus40(%s, va, sv);' % full(cc), 'C1 = C;', 'V = sV;', 'VL = sVL;', 'M = sM;', 'N = sN;', 'E = sE;') + ar_addrs(m) +
            L('local v:2 = *[DATA]:2 ap1;', 'v = v >> bt;', 'Z = v[0,1];', 'C = Z;'))


def cbs_tail(u, v, r, gt):
    return L('local pa:8 = 0;', 'local pb:8 = 0;', 'P40_0(pa);', 'P40_1(pb);', 'local diff:8 = pa - pb;',
             'local dneg:1 = (diff s< 0);', 'local cnd:1 = (dneg == 0);', 'if (%s == 0) goto <cgt>;' % gt, 'cnd = cnd && (diff != 0);', '<cgt>',
             'if (cnd == 0) goto <nc>;', 'x1 = p0h;', 'x0 = y1;', 'mixp = %s;' % r, '<nc>',
             'y0 = %s;' % u, 'local ox0:2 = x0;', 'x0 = y0;') + mul_text(0, True, True) + L(
             'local pn:8 = 0;', 'P40_0(pn);', 'local pnh:8 = pn >> 16;', 'p0h = pnh:2;', 'y0 = p0h;', 'x0 = ox0;', 'y1 = %s;' % v) + \
        mul_text(0, True, True, 'b') + mul_text(1, True, True)


@sig('cbs', 'Axh', 'CbsCond')
def _(c, ops):
    a, cc = ops
    return (L('local au:8 = sext(%s);' % full(a), 'local bv:8 = sext(%s);' % counter(a), 'local auh:8 = au >> 16;', 'local bvh:8 = bv >> 16;',
              'local gt:1 = %s;' % cc.imm, 'local uu:2 = auh:2;', 'local vv:2 = bvh:2;') + cbs_tail('uu', 'vv', 'r0', 'gt'))


@sig('cbs', 'Axh', 'Bxh', 'CbsCond')
def _(c, ops):
    a, b, cc = ops
    return (L('local au:8 = sext(%s);' % full(a), 'local bv:8 = sext(%s);' % full(b), 'local auh:8 = au >> 16;', 'local bvh:8 = bv >> 16;',
              'local gt:1 = %s;' % cc.imm, 'local uu:2 = auh:2;', 'local vv:2 = bvh:2;') + cbs_tail('uu', 'vv', 'r0', 'gt'))


@sig('cbs', 'ArpMem', 'CbsCond')
def _(c, ops):
    m, cc = ops
    return (arp_locals(m) + L('local gt:1 = %s;' % cc.imm, 'local uu:2 = *[DATA]:2 ia;', 'local vv:2 = *[DATA]:2 ja;', 'local rr:2 = ia;') +
            cbs_tail('uu', 'vv', 'rr', 'gt'))


EXPAND['mov_dvm'] = ()
EXPAND['cbs'] = ('Axh',)


# ---------------------------------------------------------------------------------------------------
# repeat, block repeat
# ---------------------------------------------------------------------------------------------------
def rep_loop(set_repc):
    return set_repc + L('<top>', 'delayslot(1);', 'if (repc == 0) goto <end>;', 'repc = repc - 1;', 'goto <top>;', '<end>')


@sig('rep', 'Imm8')
def _(c, ops):
    return rep_loop(L('repc = %s;' % ops[0].imm))


@sig('rep', 'Register')
def _(c, ops):
    return rep_loop(src16(ops[0], False, 'sv16') + L('repc = sv16;'))


@sig('rep_r6')
def _(c, ops):
    return rep_loop(L('repc = r6;'))


def block_repeat(lc, addr):
    return L('local ix:4 = zext(BCN);', 'local ps:4 = &bkstart0 + (ix * 3);',
             '*[register]:3 ps = pcv:3;', 'local pe:4 = &bkend0 + (ix * 3);', '*[register]:3 pe = %s:3;' % addr, 'local pl:4 = &bklc0 + (ix * 2);',
             '*[register]:2 pl = %s;' % lc, 'LP = 1;', 'BCN = BCN + 1;')


@sig('bkrep', 'Imm8', 'Address16')
def _(c, ops):
    i, a = ops
    return (L('local pcv:4 = inst_next;', 'pcv = pcv >> 1;', 'local ad:4 = %s;' % a.imm, 'ad = ad | (pcv & 0x30000);', 'local lc16:2 = %s;' % i.imm) +
            block_repeat('lc16', 'ad'))


@sig('bkrep', 'Register', 'Address18_16', 'Address18_2')
def _(c, ops):
    r, a, hi = ops
    return src16(r, False, 'sv16') + L('local pcv:4 = inst_next;', 'pcv = pcv >> 1;', 'local ad:4 = %s;' % a.target) + block_repeat('sv16', 'ad')


@sig('bkrep_r6', 'Address18_16', 'Address18_2')
def _(c, ops):
    a, hi = ops
    return L('local pcv:4 = inst_next;', 'pcv = pcv >> 1;', 'local ad:4 = %s;' % a.target) + block_repeat('r6', 'ad')


def stack_shift_up():
    t = ''
    for i in (3, 2, 1):
        t += L('if (BCN < %d) goto <su%d>;' % (i, i))
        for reg, size in (('bkstart', 3), ('bkend', 3), ('bklc', 2)):
            t += L('bk%s%d = bk%s%d;' % (reg[2:], i, reg[2:], i - 1)) if False else L('%s%d = %s%d;' % (reg, i, reg, i - 1))
        t += L('<su%d>' % i)
    return t


def restore_block_repeat(reg, rget, rset):
    t = L('if (LP == 0) goto <nolp>;') + stack_shift_up() + L('BCN = BCN + 1;', '<nolp>')
    t += rget + L('local fl:2 = *[DATA]:2 ad;', 'ad = ad + 1;', 'local valid:1 = fl[15,1];', 'if (LP != 0) goto <haslp>;', 'if (valid == 0) goto <haslp>;',
                  'LP = 1;', 'BCN = 1;', '<haslp>',
                  'local e16:4 = zext(*[DATA]:2 ad);', 'ad = ad + 1;', 'local s16:4 = zext(*[DATA]:2 ad);', 'ad = ad + 1;',
                  'local l16:2 = *[DATA]:2 ad;', 'ad = ad + 1;', 'local fh:4 = zext(fl >> 8) & 3;', 'local fs:4 = zext(fl) & 3;',
                  'local e4:4 = e16 | (fh << 16);', 'bkend0 = e4:3;', 'local s4:4 = s16 | (fs << 16);', 'bkstart0 = s4:3;', 'bklc0 = l16;') + rset
    return t


def store_block_repeat(rget, rset):
    t = rget + L('ad = ad - 1;', '*[DATA]:2 ad = bklc0;', 'ad = ad - 1;', 'local s0:4 = zext(bkstart0);', '*[DATA]:2 ad = s0:2;', 'ad = ad - 1;',
                 'local e0:4 = zext(bkend0);', '*[DATA]:2 ad = e0:2;', 'ad = ad - 1;', 'local s16:4 = s0 >> 16;', 'local e16:4 = e0 >> 16;',
                 'local s16w:2 = s16:2;', 'local e16w:2 = e16:2;', 'local flg:2 = (zext(LP) << 15) | s16w | (e16w << 8);', '*[DATA]:2 ad = flg;') + rset
    t += L('if (LP == 0) goto <nolp>;')
    for i in (1, 2, 3):
        t += L('if (BCN <= %d) goto <sd%d>;' % (i, i), 'bkstart%d = bkstart%d;' % (i - 1, i), 'bkend%d = bkend%d;' % (i - 1, i), 'bklc%d = bklc%d;' % (i - 1, i),
               '<sd%d>' % i)
    t += L('BCN = BCN - 1;', 'if (BCN != 0) goto <nolp>;', 'LP = 0;', '<nolp>')
    return t


RGET_ARRN = lambda m: ar_addrs(m)[:0] + L('local u:1 = 0;', 'local st:1 = 0;', 'local of:1 = 0;', 'local ri:1 = %s;' % m.imm, 'local si:1 = 0;', 'ArFields(u, st, of, ri, si);',
                                          'local ad:2 = 0;', 'RGet(ad, u);')
RSET_ARRN = L('RSet(u, ad);')


@sig('bkreprst', 'ArRn2')
def _(c, ops):
    return restore_block_repeat('r', RGET_ARRN(ops[0]), RSET_ARRN)


@sig('bkrepsto', 'ArRn2')
def _(c, ops):
    return store_block_repeat(RGET_ARRN(ops[0]), RSET_ARRN)


@sig('bkreprst_memsp')
def _(c, ops):
    return restore_block_repeat('sp', L('local ad:2 = sp;'), L('sp = ad;'))


@sig('bkrepsto_memsp')
def _(c, ops):
    return store_block_repeat(L('local ad:2 = sp;'), L('sp = ad;'))


# ---------------------------------------------------------------------------------------------------
# program memory access
# ---------------------------------------------------------------------------------------------------
ADDR_NAMES = ('movd', 'movp')


@sig('movd', 'RnStep', 'RnStep')
def _(c, ops):
    a, b = ops
    return L('local ph:4 = zext(PCMHI) << 16;', 'local pd4:4 = ph | zext(%s);' % b.disp, 'local pd:3 = pd4:3;', '*[CODE]:2 pd = *[DATA]:2 %s;' % a.disp)


@sig('movp', 'Axl', 'Register')
def _(c, ops):
    a, b = ops
    return (L('local ph:4 = zext(PCMHI) << 16;', 'local pa4:4 = ph | zext(%s);' % a.reg, 'local pa:3 = pa4:3;', 'local sv16:2 = *[CODE]:2 pa;') + wr_reg(b, 'sv16'))


@sig('movp', 'Ax', 'Register')
def _(c, ops):
    a, b = ops
    return (L('local v:8 = sext(%s);' % full(a), 'local pa4:4 = v:4 & 0x3ffff;', 'local pa:3 = pa4:3;', 'local sv16:2 = *[CODE]:2 pa;') + wr_reg(b, 'sv16'))


@sig('movp', 'RnStep', 'RnStep')
def _(c, ops):
    a, b = ops
    return L('local ph:4 = zext(PCMHI) << 16;', 'local ps4:4 = ph | zext(%s);' % a.disp, 'local ps:3 = ps4:3;', '*[DATA]:2 %s = *[CODE]:2 ps;' % b.disp)


@sig('movpdw', 'Ax')
def _(c, ops):
    return L('local v:8 = sext(%s);' % full(ops[0]), 'local pa4:4 = v:4 & 0x3ffff;', 'local pa:3 = pa4:3;', 'local pb:3 = pa + 1;', 'local h:2 = *[CODE]:2 pa;',
             'local l:2 = *[CODE]:2 pb;', 'local tgt:3 = ((zext(h) << 16) | zext(l)) & 0x3ffff;', 'goto [tgt];')
