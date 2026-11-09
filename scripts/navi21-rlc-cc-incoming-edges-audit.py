#!/usr/bin/env python3
"""Inventory decoded immediate incoming edges to three CC-related procedures."""
import hashlib,json,lzma,pathlib,re
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360]
ranges=[(0x6944,0x6e10),(0x71ac,0x72f4),(0x74c4,0x7670)]
inputs=[];edges={};unparsed=[];checked=0
for directory in ['rlc-iram-functions','rlc-vector-roots']:
 for p in sorted((E/directory).glob('*.txt')):
  inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
  for line in p.read_text().splitlines():
   m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(\S+)\s*(.*)',line)
   if not m:continue
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;checked+=1
   op=m[3];operand=m[4].split(';')[0]
   if not ((op.startswith('b') and op!='break') or op in ['j','call0','call4','call8','call12']):continue
   if op.startswith('call') or op=='j':
    v=int.from_bytes(raw,'little');off=v>>6
    if off&(1<<17):off-=1<<18
    if op.startswith('call'):
     assert v&15==5
     target=((pc+4)&~3)+4*off
     annotation=re.search(r'target=(0x[0-9a-f]+)',m[4])
     if annotation:assert target==int(annotation[1],16)
    else:
     assert v&63==6
     target=pc+4+off
   else:
    relative=re.search(r'\.\s*([+-])\s*(0x[0-9a-f]+|\d+)',operand)
    absolute=re.search(r'(0x[0-9a-f]+)\s*$',operand)
    target=pc+(1 if relative[1]=='+' else -1)*int(relative[2],0) if relative else int(absolute[1],16) if absolute else None
   if target is None:unparsed.append({'listing':str(p),'pc':hex(pc),'instruction':m[3]+' '+m[4]});continue
   edges[(pc,op,target)]={'pc':hex(pc),'operation':op,'target':hex(target),'listing':str(p)}
assert not unparsed
incoming=[]
for lo,hi in ranges:
 found=[e for (pc,op,t),e in edges.items() if lo<=t<hi and not lo<=pc<hi]
 incoming.append({'start':hex(lo),'end_exclusive':hex(hi),'edges':found})
assert {int(e['pc'],16) for e in incoming[0]['edges']}=={0x2f15,0x36ca,0x3982,0x3b32,0x3c0e,0x70a2,0x7142}
assert [e['pc'] for e in incoming[1]['edges']]==['0x6a95']
assert [e['pc'] for e in incoming[2]['edges']]==['0x6de5']
assert all(e['target']==r['start'] and e['operation']=='call8' for r in incoming for e in r['edges'])
r={'firmware_sha256':sha,'inputs':inputs,'byte_checked_records':checked,'unique_decoded_immediate_edges':len(edges),'unparsed_immediate_edges':unparsed,'incoming':incoming,'finding':'No decoded external conditional branch or immediate interior entry into these three exact procedure intervals. Nine incoming edges all target primary entries and match known CALL8 sites.','limits':['Includes saved linear/alternate listings, not a complete reachable-instruction map. No new execution claim follows from a parsed line.','Unlisted instruction streams, computed transitions, other engines and different firmware remain outside the inventory.','CALL targets are decoded from bytes using aligned PC; printed relative CALL offsets must not be added to unaligned PC. Conditional targets use byte-checked listing text.','This does not establish modified masks or hardware acceptance. No hardware access.']}
(E/'rlc-cc-incoming-edges-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'listings':len(inputs),'byte_checked_records':checked,'immediate_edges':len(edges),'incoming_edges':sum(len(x['edges']) for x in incoming),'interior_incoming':0}))
