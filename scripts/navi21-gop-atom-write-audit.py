#!/usr/bin/env python3
"""Offline byte-checked stock ATOM destination inventory; not a full emulator."""
import hashlib
import json
from pathlib import Path
import struct

root = Path('evidence/navi21-unlock/disassembly-v1')
reference = json.loads(Path('evidence/navi21-unlock/xt-rom-comparison-v1/full-reference-comparison.json').read_text())
gop = json.loads((root/'gop-inventory.json').read_text())
image = next(x for x in gop['images'] if x['variant']=='baseline' and x['machine']=='0x8664')
pe = Path(image['extracted']).read_bytes()
assert hashlib.sha256(pe).hexdigest()==image['sha256']
writers = {'move','and','or','mul','div','add','sub','xor','shl','shr','mul32','div32',
           'mask','clear','shift_left','shift_right'}
reports=[]
for variant in ('baseline','candidate'):
    ref=reference[variant]; rom=Path(ref['path']).read_bytes()
    assert hashlib.sha256(rom).hexdigest()==ref['sha256']
    writes=[];base_mutations=[];calls=[];dispatch={};indexed_pairs=[]
    for table in ref['tables']['command']:
        rows=reference['command_disassembly'][str(table['index'])][variant]
        incoming={r['offset']:[] for r in rows}
        for i,row in enumerate(rows):
            nxt=rows[i+1]['offset'] if i+1<len(rows) else None
            if row['op']=='jump':
                edges=[row['value']]+([] if row['condition']=='ATOM_COND_ALWAYS' else [nxt])
            elif row['op']=='switch':
                edges=[c['target'] for c in row['cases']]+[nxt]
            elif row['op']=='eot':edges=[]
            else:edges=[nxt]
            for target in edges:
                if target is not None:incoming[target].append(row['offset'])
        for row in rows:
            raw=bytes.fromhex(row['hex']);off=table['offset']+row['offset']
            assert rom[off:off+len(raw)]==raw
            operands=row['operands'];dest=operands[0] if operands else None
            if row['op']=='setregblock' or (row['op'] in writers and dest and dest['kind']=='WS' and dest['value']==0x48):
                base_mutations.append(dict(table=table['index'],row=row))
            if row['op']=='calltable':calls.append(dict(table=table['index'],offset=row['offset'],callee=row['value']))
            if row['op'] in writers and dest and dest['kind']=='REG':
                index=dest['value']
                writes.append(dict(table=table['index'],offset=hex(row['offset']),operation=row['op'],
                    index=hex(index),byte_offset_if_base_zero=hex(index*4),operands=operands,
                    index_port=index==0,data_port=index==1))
                if index==1:
                    preds=incoming[row['offset']]
                    assert len(preds)==1
                    previous=next(x for x in rows if x['offset']==preds[0])
                    assert previous['op']=='move' and previous['operands'][0]['kind']=='REG'
                    assert previous['operands'][0]['value']==0 and previous['operands'][1]['kind']=='IMM'
                    selector=previous['operands'][1]['value']
                    indexed_pairs.append(dict(table=table['index'],data_pc=hex(row['offset']),
                        sole_predecessor=hex(preds[0]),selector=hex(selector),
                        selector_after_gop_shift=hex((selector<<2)&0xffffffff)))
                opcode=raw[0]
                if variant=='baseline':
                    target,arg,length=struct.unpack_from('<QBB',pe,0xbcb0+10*opcode)
                    assert arg==0 # GOP destination type REG
                    dispatch[str(opcode)]=dict(handler=hex(target),destination_type=arg,header_bytes=length)
    assert not base_mutations
    reports.append(dict(variant=variant,rom_sha256=ref['sha256'],tables=len(ref['tables']['command']),
        writes=writes,base_mutations=base_mutations,table_calls=calls,
        indexed_pairs=indexed_pairs,
        direct_cc_matches=[x for x in writes if int(x['index'],16) in (0x2249,0x226f)],
        gop_dispatch=dispatch))
result=dict(scope='All parsed stock command rows, including unreachable branches; initial zero base established in XL GOP. REG0/1 indirect values remain separate.',reports=reports)
(root/'gop-atom-write-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps([dict(variant=r['variant'],tables=r['tables'],writes=len(r['writes']),direct_cc=len(r['direct_cc_matches']),index_data_writes=sum(x['index_port'] or x['data_port'] for x in r['writes'])) for r in reports]))
