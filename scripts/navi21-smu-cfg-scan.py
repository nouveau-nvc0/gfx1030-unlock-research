#!/usr/bin/env python3
"""Conservative local constant propagation over targeted SMU listings.

This is a locator, not a firmware verifier: memory loads, call returns, unknown
operations and disagreeing predecessor values become unknown. No hardware I/O.
"""
import argparse
import collections
import json
import pathlib
import re

p = argparse.ArgumentParser()
p.add_argument('listings', nargs='+')
p.add_argument('--output', required=True)
p.add_argument('--indirect-edges', help='Offline initial-table edges, keyed by listing basename then JX PC')
a = p.parse_args()
indirect_edges = json.loads(pathlib.Path(a.indirect_edges).read_text())['edges'] if a.indirect_edges else {}
reports = []
for filename in a.listings:
    code = {}
    sizes = {}
    for line in pathlib.Path(filename).read_text().splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(\S+)\s*(.*)', line)
        if m:
            code[int(m[1], 16)] = (m[3], m[4], line)
            sizes[int(m[1], 16)] = len(m[2]) // 2
    if not code:
        continue
    pcs = sorted(code)
    nxt = {pc:pc+sizes[pc] for pc in pcs if pc+sizes[pc] in code}
    # Appended shared branch bodies may precede the actual entry address.
    entry = next(iter(code))
    incoming = {entry: {}}
    queue = collections.deque([entry])
    edges_out = set()
    unknown_ops = set()
    # Xtensa zero-overhead loops branch implicitly when the body reaches
    # LEND. Add the repeat edge as well as normal fall-through, regardless
    # of the (possibly unknown) iteration count.
    loop_back = collections.defaultdict(set)
    for loop_pc, (loop_op, operand, _) in code.items():
        if loop_op not in ('loop', 'loopnez', 'loopgtz'):
            continue
        absolute = re.search(r'(0x[0-9a-f]+)\s*(?:;.*)?$', operand)
        relative = re.search(r'\.\s*([+-])\s*(0x[0-9a-f]+|\d+)', operand)
        end = (loop_pc + (1 if relative[1] == '+' else -1)*int(relative[2], 0)
               if relative else int(absolute[1], 16) if absolute else None)
        body = nxt.get(loop_pc)
        predecessors = [pc for pc in pcs if nxt.get(pc) == end]
        if body is not None and predecessors:
            loop_back[predecessors[0]].add(body)
        else:
            edges_out.add((hex(loop_pc), 'unresolved hardware-loop end'))

    def arguments(s):
        return [x.strip() for x in s.split(';')[0].split(',')]

    def val(s, state):
        if re.fullmatch(r'a\d+', s):
            return state.get(s)
        try:
            return int(s, 0) & 0xffffffff
        except ValueError:
            return None

    def process(pc, state):
        op, operand, raw = code[pc]
        op = op.removesuffix('.n')
        args = arguments(operand)
        out = dict(state)
        dest = args[0] if args and re.fullmatch(r'a\d+', args[0]) else None
        value = None
        known = True
        if op == 'l32r':
            m = re.search(r'\((0x[0-9a-f]+)\)', operand)
            value = int(m[1], 16) if m else None
        elif op in ('movi', 'mov'):
            value = val(args[1], state)
        elif op in ('add', 'addi', 'addmi', 'sub', 'and', 'or', 'xor',
                    'addx2', 'addx4', 'addx8', 'subx8', 'slli', 'srli'):
            x, y = (val(t, state) for t in args[1:3])
            if x is not None and y is not None:
                if op.startswith('addx'):
                    value = x * int(op[-1]) + y
                elif op == 'subx8':
                    value = 8*x-y
                else:
                    value = {'add': lambda: x+y, 'addi': lambda: x+y,
                             'addmi': lambda: x+y, 'sub': lambda: x-y,
                             'and': lambda: x&y, 'or': lambda: x|y,
                             'xor': lambda: x^y, 'slli': lambda: x << (y&31),
                             'srli': lambda: x >> (y&31)}[op]()
        elif op == 'extui':
            x, shift, width = (val(t, state) for t in args[1:4])
            if None not in (x, shift, width):
                value = (x >> shift) & ((1 << width)-1)
        elif op in ('moveqz', 'movnez'):
            source, condition = (val(t, state) for t in args[1:3])
            previous = state.get(dest)
            if condition is not None:
                take = (condition == 0) if op == 'moveqz' else (condition != 0)
                value = source if take else previous
            elif source == previous:
                value = source
        elif op in ('movt', 'movf'):
            # Boolean-controlled integer move: only the destination changes.
            # Boolean register values are not tracked. Preserve a value only
            # when both alternatives agree; other integer registers survive.
            source = val(args[1], state)
            previous = state.get(dest)
            value = source if source == previous else None
        elif op in ('sll', 'srl', 'sra', 'src', 'neg', 'abs', 'sext',
                    'minu', 'maxu', 'min', 'max', 'mull', 'quos', 'quou',
                    'remu', 'rems', 'rfr', 'ceil.s', 'floor.s', 'round.s',
                    'trunc.s', 'utrunc.s'):
            # Single integer destination; result intentionally unknown.
            pass
        elif op.startswith('call'):
            # CALL8 window convention; other variants are conservative barriers.
            keep = range(8, 16) if op in ('call8', 'callx8') else range(16)
            for i in keep:
                out.pop(f'a{i}', None)
            return out
        elif op in ('ssip', 'ssxp', 'lsip', 'lsxp'):
            # Post-increment changes the integer address register.
            out.pop(args[1], None)
            return out
        elif op in ('wfr', 'lsi', 'lsx', 'mul.s', 'ufloat.s', 'const.s',
                    'olt.s', 'sub.s', 'madd.s', 'float.s', 'add.s', 'movt.s',
                    'mov.s', 'ole.s', 'abs.s', 'movf.s', 'msub.s', 'neg.s',
                    'movnez.s', 'maddn.s', 'addexp.s', 'addexpm.s', 'divn.s',
                    'mksadj.s', 'nexp01.s', 'sqrt0.s', 'recip0.s'):
            # These affect FP/boolean registers, not integer address registers.
            return out
        elif op.startswith(('s32i', 's16i', 's8i', 'b', 'ret', 'loop')) or op in ('s32e', 'ssi', 'ssx', 'j', 'jx', 'memw', 'dsync', 'isync', 'rsync', 'nop', 'ssl', 'ssr', 'ssai', 'wsr.ps', 'wsr.misc1', 'dhwbi', 'dhi', 'ihi'):
            return out
        elif op == 'entry':
            return {}
        elif op.startswith(('l32i', 'l16', 'l8', 'rsr', 'rsil')):
            pass
        else:
            known = False
        if not known:
            unknown_ops.add(op)
            # Unknown instruction may change multiple integer registers.
            return {}
        if dest:
            out.pop(dest, None)
            if value is not None:
                out[dest] = value & 0xffffffff
        return out

    def successors(pc):
        op, operand, _ = code[pc]
        if op in ('rfe', 'rfi', 'rfwo', 'rfwu', 'rfde'):
            edges_out.add((hex(pc), 'exception return; dynamic resumption outside local CFG'))
            return []
        if op.startswith('ret') or op in ('ill', 'excw'):
            return []
        if op in ('break', 'break.n'):
            edges_out.add((hex(pc), 'debug exception; handler/resumption unresolved'))
            return []
        if op == 'jx':
            targets = indirect_edges.get(pathlib.Path(filename).name, {}).get(hex(pc))
            if targets is not None:
                result = []
                for value in targets:
                    target = int(value, 0)
                    if target in code:
                        result.append(target)
                    else:
                        edges_out.add((hex(pc), hex(target)))
                return result
            edges_out.add((hex(pc), 'indirect jump ' + operand.split(';')[0].strip()))
            return []
        fall = ([nxt[pc]] if pc in nxt else []) + sorted(loop_back.get(pc, ()))
        if op == 'j' or op.startswith(('b', 'loop')):
            m = re.search(r'(0x[0-9a-f]+)\s*(?:;.*)?$', operand)
            rel = re.search(r'\.\s*([+-])\s*(0x[0-9a-f]+|\d+)', operand)
            target = (pc + (1 if rel[1] == '+' else -1)*int(rel[2], 0) if rel else int(m[1], 16) if m else None)
            if target not in code:
                edges_out.add((hex(pc), hex(target) if target is not None else 'unknown'))
            return ([target] if target in code else []) + ([] if op == 'j' else fall)
        return fall

    while queue:
        pc = queue.popleft()
        out = process(pc, incoming[pc])
        for target in successors(pc):
            old = incoming.get(target)
            merged = out if old is None else {k:v for k,v in old.items() if out.get(k) == v}
            if old is None or merged != old:
                incoming[target] = merged
                queue.append(target)
    stores = []
    for pc, state in sorted(incoming.items()):
        op, operand, _ = code[pc]
        if op.removesuffix('.n') not in ('s32i', 's16i', 's8i', 'ssi', 'ssip', 'ssx', 'ssxp', 's32c1i', 's32e'):
            continue
        arg = arguments(operand)
        base, offset = val(arg[1], state), val(arg[2], state)
        address = (base+offset)&0xffffffff if base is not None and offset is not None else None
        alternatives = []
        if op in ('ssip', 'ssxp'):
            # Decoder configuration is not attested for this FPU option.
            # Keep both pre/post-update coordinates; do not invent precision.
            alternatives = sorted({x for x in (base, address) if x is not None})
            address = None
        stores.append({'pc':hex(pc), 'operation':op, 'address':hex(address) if address is not None else None,
                       'address_candidates':[hex(x) for x in alternatives],
                       'source':arg[0], 'source_constant':state.get(arg[0]),
                       'base':arg[1], 'offset':arg[2]})
    calls = []
    for pc, state in sorted(incoming.items()):
        op, operand, line = code[pc]
        if op.startswith('call'):
            target = re.search(r'target=(0x[0-9a-f]+)', line)
            calls.append({'pc':hex(pc), 'operation':op,
                          'target':target[1] if target else None,
                          'integer_constants':{k:hex(v) for k,v in sorted(state.items())}})
    reports.append({'listing':filename, 'reachable_in_window':len(incoming), 'calls':calls,
                    'hardware_loop_backedges':[(hex(pc), hex(target)) for pc in sorted(loop_back) for target in sorted(loop_back[pc])],
                    'decoded_in_window':len(code), 'unresolved_or_external_edges':sorted(edges_out),
                    'reached_stop_instructions':[{'pc':hex(pc),'operation':code[pc][0]}
                        for pc in sorted(incoming) if code[pc][0] in ('excw','ill')],
                    'missing_fallthrough':[hex(pc) for pc in sorted(incoming)
                        if pc not in nxt and not code[pc][0].startswith('ret')
                        and code[pc][0] not in ('j','jx','ill','excw','rfe','rfi','rfwo','rfwu','rfde','break','break.n')],
                    'unknown_operations':sorted(unknown_ops), 'stores':stores})
pathlib.Path(a.output).write_text(json.dumps({'scope':'Local targeted-listing locator; no memory-value propagation or global completeness claim. Optional JX edges describe initial tables, not runtime immutability.', 'indirect_edges':a.indirect_edges, 'reports':reports}, indent=2)+'\n')
