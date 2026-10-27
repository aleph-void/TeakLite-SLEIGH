"""Operand kinds and helpers for the Teak SLEIGH generator (see gen_teak.py)."""
import itertools

BITS = {
    'Ax': 1, 'Axl': 1, 'Axh': 1, 'Bx': 1, 'Bxl': 1, 'Bxh': 1, 'Px': 1,
    'Ab': 2, 'Abl': 2, 'Abh': 2, 'Abe': 2, 'Ablh': 3, 'RnOld': 3, 'Rn': 3, 'R45': 1, 'R0123': 2,
    'ArArpSttMod': 4, 'ArArp': 3, 'SttMod': 3, 'Ar': 1, 'Arp': 2, 'SwapType': 4,
    'ArRn1': 1, 'ArRn2': 2, 'ArStep1': 1, 'ArStep1Alt': 1, 'ArStep2': 2,
    'ArpRn1': 1, 'ArpRn2': 2, 'ArpStep1': 1, 'ArpStep2': 2,
    'Address18_2': 2, 'Address18_16': 16, 'Address16': 16, 'RelAddr7': 7,
    'Imm2': 2, 'Imm4': 4, 'Imm5': 5, 'Imm5s': 5, 'Imm6s': 6, 'Imm7s': 7, 'Imm8': 8, 'Imm8s': 8, 'Imm9': 9, 'Imm16': 16,
    'MemImm8': 8, 'MemImm16': 16, 'MemR7Imm7s': 7, 'MemR7Imm16': 16,
    'Alm': 4, 'Alu': 3, 'Alb': 3, 'Mul3': 3, 'Mul2': 2, 'Moda4': 4, 'Moda3': 3, 'Cond': 4, 'BankFlags': 6,
    'CbsCond': 1, 'StepZIDS': 2, 'Register': 5,
}
SIGNED = {'Imm5s', 'Imm6s', 'Imm7s', 'Imm8s', 'MemR7Imm7s', 'RelAddr7'}

ATTACH = {
    'Ax': ['a0', 'a1'], 'Axl': ['a0l', 'a1l'], 'Axh': ['a0h', 'a1h'], 'Bx': ['b0', 'b1'], 'Bxl': ['b0l', 'b1l'],
    'Bxh': ['b0h', 'b1h'], 'Px': ['p0', 'p1'], 'Ab': ['b0', 'b1', 'a0', 'a1'], 'Abl': ['b0l', 'b1l', 'a0l', 'a1l'],
    'Abh': ['b0h', 'b1h', 'a0h', 'a1h'], 'Abe': ['b0e', 'b1e', 'a0e', 'a1e'],
    'Ablh': ['b0l', 'b0h', 'b1l', 'b1h', 'a0l', 'a0h', 'a1l', 'a1h'],
    'RnOld': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r7', 'y0'],
    'Rn': ['r%d' % i for i in range(8)], 'R45': ['r4', 'r5'], 'R0123': ['r0', 'r1', 'r2', 'r3'],
    'Ar': ['ar0', 'ar1'], 'Arp': ['arp0', 'arp1', 'arp2', 'arp3'],
    'Register': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r7', 'y0', 'st0', 'st1', 'st2', 'p0h', 'pc16', 'sp', 'cfgi', 'cfgj',
                 'b0h', 'b1h', 'b0l', 'b1l', 'ext0', 'ext1', 'ext2', 'ext3', 'a0l', 'a1l', 'a0l', 'a1l', 'a0h', 'a1h', 'lc', 'sv'],
}
# full accumulator behind the partial kinds (second field over the same bits), and how to index it
FULL = {'Axl': 'Ax', 'Axh': 'Ax', 'Bxl': 'Bx', 'Bxh': 'Bx', 'Abl': 'Ab', 'Abh': 'Ab', 'Abe': 'Ab'}

ENUM = {
    'Alm': ['or', 'and', 'xor', 'add', 'tst0', 'tst1', 'cmp', 'sub', 'msu', 'addh', 'addl', 'subh', 'subl', 'sqr', 'sqra', 'cmpu'],
    'Alu': ['or', 'and', 'xor', 'add', None, None, 'cmp', 'sub'],
    'Alb': ['set', 'rst', 'chng', 'addv', 'tst0', 'tst1', 'cmpv', 'subv'],
    'Mul3': ['mpy', 'mpysu', 'mac', 'macus', 'maa', 'macuu', 'macsu', 'maasu'],
    'Mul2': ['mpy', 'mac', 'maa', 'macsu'],
    'Moda4': ['shr', 'shr4', 'shl', 'shl4', 'ror', 'rol', 'clr', None, 'not', 'neg', 'rnd', 'pacr', 'clrr', 'inc', 'dec', 'copy'],
    'Moda3': ['shr', 'shr4', 'shl', 'shl4', 'ror', 'rol', 'clr', 'clrr'],
    'SwapType': ['a0,b0', 'a0,b1', 'a1,b0', 'a1,b1', 'a0:a1,b0:b1', 'a0:a1,b1:b0', 'a1,b0,a0', 'a1,b1,a0',
                 'a0,b0,a1', 'a0,b1,a1', 'b1,a0,b0', 'b1,a1,b0', 'b0,a0,b1', 'b0,a1,b1', None, None],
}
SWAP_NAMES = ['a0b0', 'a0b1', 'a1b0', 'a1b1', 'a0b0a1b1', 'a0b1a1b0', 'a0b0a1', 'a0b1a1', 'a1b0a0', 'a1b1a0',
              'b0a0b1', 'b0a1b1', 'b1a0b0', 'b1a1b0']
COND = ['always', 'eq', 'neq', 'gt', 'ge', 'lt', 'le', 'nn', 'c', 'v', 'e', 'l', 'nr', 'niu0', 'iu0', 'iu1']
STEPS = ['', '++', '--', '++s']
