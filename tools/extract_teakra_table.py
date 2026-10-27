#!/usr/bin/env python3
"""Extract the instruction encoding table from teakra's src/decoder.h (MIT, (c) 2018 Weiyi Wang).
Only the encoding facts (name, opcode, operand kinds/positions, excluded values) are taken, not any code.
usage: extract_teakra_table.py <teakra>/src/decoder.h > teak_insts.json"""
import re, sys, json
src = open(sys.argv[1]).read()
body = src[src.index('return {'):src.index('#undef INST')]
body = body[body.index('\n')+1:]
body = re.sub(r'#define[^\n]*', '', body)
body = re.sub(r'//[^\n]*', '', body)
entries = []
i = body.index('INST(')
for m in re.finditer(r'INST\(', body):
    s = m.start() + 5
    depth = 1; j = s
    while depth:
        c = body[j]
        depth += (c == '(') - (c == ')')
        j += 1
    inner = body[s:j-1]
    rest = body[j:]
    exc = []
    while True:
        mm = re.match(r'\s*\.EXCEPT\(AtConst<(\w+),\s*(\d+),\s*(\d+)>\)', rest)
        if not mm: break
        exc.append((mm.group(1), int(mm.group(2)), int(mm.group(3)))); rest = rest[mm.end():]
    # split top level commas
    parts = []; d = 0; cur = ''
    for c in inner:
        if c == '<': d += 1
        if c == '>': d -= 1
        if c == ',' and d == 0:
            parts.append(cur.strip()); cur = ''
        else:
            cur += c
    parts.append(cur.strip())
    name = parts[0]; opcode = int(parts[1], 16)
    ops = []
    for p in parts[2:]:
        mm = re.match(r'(AtNamed|At|Const|Unused)<(.*)>$', p)
        if mm:
            a = [x.strip() for x in mm.group(2).split(',')]
            if mm.group(1) == 'Unused': ops.append(('Unused', int(a[0])))
            else: ops.append((mm.group(1), a[0], int(a[1])))
        else:
            ops.append(('Cn', p))
    entries.append({'name': name, 'opcode': opcode, 'ops': ops, 'except': exc})
json.dump(entries, sys.stdout, indent=0)
