#!/usr/bin/env python3
"""Compare saved Navi21 ATOM ROMs offline. Never accesses hardware or executes ROM code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def digest(b):
    return hashlib.sha256(b).hexdigest()


def u16(b, p):
    return struct.unpack_from('<H', b, p)[0]


def names(header, name):
    body = header.split('struct ' + name + '{', 1)[1].split('};', 1)[0]
    return re.findall(r'uint16_t\s+(\w+)\s*;', body)


def table(b, p):
    assert 0 < p <= len(b) - 4
    n, f, c = struct.unpack_from('<HBB', b, p)
    assert n >= 4 and p + n <= len(b)
    return dict(offset=p, bytes=n, format=f, content=c, sha256=digest(b[p:p+n]))


def inventory(path, field_names, offsets):
    b = path.read_bytes()
    assert b[:2] == b'\x55\xaa'
    h = u16(b, 0x48)
    assert b[h+4:h+8] == b'ATOM'
    masters = dict(command=u16(b, h+30), data=u16(b, h+32))
    out = dict(path=str(path.resolve()), bytes=len(b), sha256=digest(b),
               md5=hashlib.md5(b).hexdigest(), sha1=hashlib.sha1(b).hexdigest(),
               subsystem='%04x:%04x' % struct.unpack_from('<HH', b, h+24),
               identifiers=[m.group().decode('ascii') for m in re.finditer(rb'113-[A-Za-z0-9_-]+', b[:45056])],
               tables={})
    blobs = {}
    for kind, p in masters.items():
        m = table(b, p)
        out['tables'][kind] = []
        for i in range((m['bytes']-4)//2):
            q = u16(b, p+4+2*i)
            if not q:
                continue
            t = table(b, q)
            t.update(index=i, name=field_names[kind][i])
            out['tables'][kind].append(t)
            blobs[kind, i] = b[q:q+t['bytes']]
    psp = struct.unpack_from('<I', b, h+36)[0]
    assert b[psp:psp+4] == b'$PSP'
    count = struct.unpack_from('<I', b, psp+8)[0]
    assert count <= 256 and psp+16+16*count <= len(b)
    out['psp_directory'] = []
    for i in range(count):
        typ, size, offset = struct.unpack_from('<IIQ', b, psp+16+16*i)
        complete = offset+size <= len(b)
        out['psp_directory'].append(dict(type=typ, offset=offset, bytes=size,
            complete=complete, sha256=digest(b[offset:offset+size]) if complete else None))
    gfx = blobs['data', 14]
    out['gfx_info'] = dict(max_shader_engines=gfx[6], max_cu_per_sh=gfx[8],
        max_sh_per_se=gfx[9], max_backends_per_se=gfx[10],
        bytes_44_47_hex=gfx[44:48].hex(),
        interpretation='v2.6 undocumented here; v3.0 common-layout hypothesis: WGP/SE, RB/SE, active SE, reserved',
        hypothesized_wgp_per_se=gfx[44], hypothesized_active_se=gfx[46],
        hypothesized_cu_total=gfx[44]*gfx[46]*2)
    pp = blobs['data', 15]
    assert len(pp) == offsets['pp_table_size']
    base = offsets['smu_11_0_7_powerplay_table.smc_pptable']
    fields = [('SocketPowerLimitAc', 4), ('SocketPowerLimitDc', 4),
              ('FreqTableGfx', 16), ('FreqTableUclk', 4),
              ('GfxclkFinit', 1), ('GfxclkFidle', 1)]
    out['powerplay'] = {f:list(struct.unpack_from('<'+'H'*n, pp, base+offsets['PPTable_t.'+f])) for f,n in fields}
    out['pcir_images'] = []
    start = 0
    while b[start:start+2] == b'\x55\xaa':
        p = start + u16(b, start+0x18)
        assert b[p:p+4] == b'PCIR'
        size = u16(b, p+0x10)*512
        assert size > 0
        complete = start+size <= len(b)
        out['pcir_images'].append(dict(offset=start, bytes=size, code_type=b[p+0x14],
            last=bool(b[p+0x15]&128), complete=complete,
            sum8=sum(b[start:start+size])%256 if complete else None,
            sha256=digest(b[start:start+size]) if complete else None))
        if not complete or b[p+0x15]&128:
            break
        start += size
    return out, blobs


def disassemble(blob, opcodes):
    """Linear instruction framing from Linux's interpreter; no branch execution."""
    argmap = dict(REG=0, PS=1, WS=2, FB=3, ID=4, IMM=5, PLL=6, MC=7)
    argnames = list(argmap)
    sizes = [4, 2, 2, 2, 1, 1, 1, 1]
    p = 6
    rows = []
    def get(n):
        nonlocal p
        assert p+n <= len(blob), ('operand overrun', p, n, len(blob))
        v = int.from_bytes(blob[p:p+n], 'little')
        p += n
        return v
    def operand(arg, align=0):
        n = sizes[align] if arg == 5 else 2 if arg in [0,4] else 1
        byte_offset = p
        return dict(kind=argnames[arg], value=get(n), alignment=align, byte_offset=byte_offset)
    binary = {'move','and','or','mul','div','add','sub','compare','test','xor','shl','shr','mul32','div32'}
    while p < len(blob):
        start = p
        op = get(1)
        assert 0 < op < len(opcodes), ('unknown opcode', op, start)
        func, arg = opcodes[op]
        func = func.removeprefix('atom_op_')
        row = dict(offset=start, op=func, operands=[])
        if arg.startswith('ATOM_ARG_'):
            dstarg = argmap[arg.removeprefix('ATOM_ARG_')]
        else:
            dstarg = None
        if func in binary | {'mask','clear','shift_left','shift_right'}:
            attr = get(1)
            row['attr'] = attr
            align = (attr>>3)&7
            dst_align = [[0]*4, [1,2,3,0], [1,2,3,0], [1,2,3,0],
                         [4,5,6,7], [4,5,6,7], [4,5,6,7], [4,5,6,7]][align][attr>>6]
            if func in {'clear','shift_left','shift_right'}:
                dst_align = align
            row['operands'].append(operand(dstarg, dst_align))
            if func == 'mask':
                row['mask'] = get(sizes[align])
            if func in {'shift_left','shift_right'}:
                row['shift'] = get(1)
            elif func != 'clear':
                row['operands'].append(operand(attr&7, align))
        elif func in {'setfbbase','switch'}:
            attr = get(1)
            row['attr'] = attr
            row['operands'].append(operand(attr&7, (attr>>3)&7))
            if func == 'switch':
                cases = []
                while u16(blob, p) != 0x5a5a:
                    assert get(1) == 0x63
                    cases.append(dict(value=get(sizes[(attr>>3)&7]), target=get(2)))
                get(2)
                row['cases'] = cases
        elif func in {'setregblock','jump'}:
            row['value'] = get(2)
            row['condition'] = arg
        elif func == 'setport':
            row['port'] = get(2 if arg=='ATOM_PORT_ATI' else 1)
            row['type'] = arg
        elif func in {'delay','calltable','postcard','debug','setdatablock'}:
            row['value'] = get(1)
        elif func == 'processds':
            n = get(2)
            row['data_bytes'] = n
            get(n)
        elif func not in {'eot','nop','beep'}:
            raise ValueError(('unsupported opcode', start, func))
        row['hex'] = blob[start:p].hex()
        rows.append(row)
    assert p == len(blob)
    boundaries = {r['offset'] for r in rows}
    for r in rows:
        if r['op'] == 'jump':
            assert r['value'] in boundaries, ('bad jump', r)
        for case in r.get('cases', []):
            assert case['target'] in boundaries
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--baseline', type=Path, required=True)
    ap.add_argument('--candidate', type=Path, required=True)
    ap.add_argument('--sources', type=Path, default=Path('evidence/navi21-unlock/sources'))
    ap.add_argument('--offsets', type=Path, default=Path('evidence/navi21-unlock/pptable-offsets.json'))
    ap.add_argument('--atom-header', type=Path, default=Path('evidence/navi21-unlock/xt-rom-comparison-v1/atom.h'))
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    header = (a.sources/'atomfirmware.h').read_text()
    field_names = dict(data=names(header, 'atom_master_list_of_data_tables_v2_1'),
                       command=names(header, 'atom_master_list_of_command_functions_v2_1'))
    src = (a.sources/'amdgpu_atom.c').read_text()
    opsrc = src.split('} opcode_table[ATOM_OP_CNT] = {',1)[1].split('\n};',1)[0]
    opcodes = re.findall(r'\{\s*(NULL|atom_op_\w+),\s*([A-Z_0-9]+)\s*\}', opsrc)
    assert len(opcodes) == 127
    atom_header = a.atom_header.read_text()
    for i, name in enumerate(['REG','PS','WS','FB','ID','IMM','PLL','MC']):
        assert re.search(r'#define\s+ATOM_ARG_'+name+r'\s+'+str(i)+r'\b', atom_header)
    offsets = json.loads(a.offsets.read_text())
    A, ab = inventory(a.baseline, field_names, offsets)
    B, bb = inventory(a.candidate, field_names, offsets)
    comparisons = []
    commands = {}
    for key in sorted(ab.keys() | bb.keys()):
        x, y = ab.get(key,b''), bb.get(key,b'')
        kind, i = key
        d = dict(kind=kind, index=i, name=field_names[kind][i], identical=x==y,
                 baseline_bytes=len(x), candidate_bytes=len(y),
                 baseline_sha256=digest(x), candidate_sha256=digest(y),
                 differences=[dict(offset=j, baseline=x[j] if j<len(x) else None,
                                   candidate=y[j] if j<len(y) else None)
                              for j in range(max(len(x),len(y)))
                              if (x[j:j+1] != y[j:j+1])])
        comparisons.append(d)
        if kind == 'command':
            commands[str(i)] = dict(baseline=disassemble(x,opcodes), candidate=disassemble(y,opcodes))
    adir = {r['type']:r for r in A['psp_directory']}
    bdir = {r['type']:r for r in B['psp_directory']}
    psp_comparisons = [dict(type=t, comparable=adir[t]['complete'] and bdir[t]['complete'],
        identical=(adir[t]['sha256']==bdir[t]['sha256'] and adir[t]['bytes']==bdir[t]['bytes'])
        if adir[t]['complete'] and bdir[t]['complete'] else None) for t in sorted(adir.keys() & bdir.keys())]
    summary = dict(baseline=A, candidate=B, comparisons=comparisons, command_disassembly=commands,
        psp_payload_comparisons=psp_comparisons,
        source_sha256={str(p):digest(p.read_bytes()) for p in [a.sources/'atomfirmware.h', a.sources/'amdgpu_atom.c', a.offsets, a.atom_header]},
        limitations=['Baseline is a VFCT POST copy, not a physical flash dump.',
            'Downloaded complete ROMs were not observed running on this host.',
            'Linear ATOM decoding does not trace GOP/x86/PSP/SMU or prove execution effects.',
            'GFX_INFO 2.6 active-count interpretation uses a cross-version layout hypothesis.'])
    a.output.write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(dict(baseline=A['sha256'], candidate=B['sha256'],
        same_tables=[d['name'] for d in comparisons if d['identical']],
        different_tables=[dict(name=d['name'], changed_bytes=len(d['differences'])) for d in comparisons if not d['identical']],
        instructions={k:len(v['candidate']) for k,v in commands.items()}),indent=2))


if __name__ == '__main__':
    main()
