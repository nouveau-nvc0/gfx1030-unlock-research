#!/usr/bin/env python3
"""Address model for RLC74c4's indexed hardware snapshots; offline only."""
import hashlib,json,lzma,re
from pathlib import Path
r=Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0';code=b[0xb360:0x1b360]
checks={}
for name in ('06944','074c4'):
 lines=(r/'rlc-iram-functions'/f'{name}.txt').read_text();count=0
 for line in lines.splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;count+=1
 checks[name]=dict(instruction_bytes_checked=count,listing_sha256=hashlib.sha256(lines.encode()).hexdigest())
base=0x5ffedc80;offsets=(0xc,0x10,0x10c,0x110,0x20c,0x210)
regions={'cc_wgp':(0x5ffedfc4,0x5ffedfe4),'cc_rb':(0x5ffedfe4,0x5ffee004),'user_wgp':(0x5ffee004,0x5ffee024),'user_rb':(0x5ffee024,0x5ffee044),'restore_gate':(0x5ffee452,0x5ffee453)}
def overlaps(slot):
 result=[]
 for off in offsets:
  address=base+8*slot+off
  for name,(start,end) in regions.items():
   if address<end and address+4>start:result.append(dict(region=name,address=hex(address),offset=hex(off)))
 return result
assert all(not overlaps(s) for s in range(32))
known=[('2f15',1,0),('36ca',1,1),('3982',0,0x01000001),('3b32',1,1),('3c0e',0,0),('70a2',0,0),('7142',1,0)]
callers=[]
for pc,first,second in known:
 custom=(second>>8)&255;index=(second>>16)&255;slot=index if custom else 31
 assert slot==31
 callers.append(dict(pc=pc,first_word=hex(first),second_word=hex(second),selector_enable=custom,slot=slot,overlaps=overlaps(slot)))
possible=[dict(slot=s,overlaps=overlaps(s)) for s in range(256) if overlaps(s)]
report=dict(scope='Address calculation from byte-checked listings; seven caller words retain prior manual provenance in rlc-srm-operation-followup.txt. No hardware execution or arbitrary-index reachability proof.',firmware_sha256=sha,checked=checks,known_callers=callers,
 modeled_custom_slot_overlaps=possible,gate_overlaps=[x for x in possible if any(y['region']=='restore_gate' for y in x['overlaps'])],
 limitation='Stores are hardware register snapshots conditional on source status bit7 and operation=0. Overlap is not control of arbitrary values or proof these custom slots occur.')
(r/'rlc-saved-array-overlap.json').write_text(json.dumps(report,indent=2)+'\n')
print('Seven known callers select31: no saved-CC/gate overlap. Custom slot range modeled:256.')
print('First CC_WGP overlap:',next(x for x in possible if any(y['region']=='cc_wgp' for y in x['overlaps'])))
print('Gate overlaps:',report['gate_overlaps'])
