#!/usr/bin/env python3
"""Byte-checked destination bounds for the six computed stores in01d10."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
p=E/'rlc-iram-functions/01d10.txt'
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
records={}
for line in p.read_text().splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
 if m:
  pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[0xb360+pc:0xb360+pc+len(raw)]==raw;records[pc]=(m[2],m[3])
# Address initialization, increments, stores, exits, and third-loop reload.
expected={0x1d46:'a133ed',0x1d4c:'c2ca40',0x1e1b:'8baa',0x1e29:'926a41',0x1e2c:'826a42',0x1e2f:'c79ae2',0x1e34:'a1faec',0x1e3d:'a901',0x1e44:'f26a23',0x1e47:'d26a33',0x1e4a:'a2ca04',0x1e4d:'c71a29',0x1e7a:'a801',0x1e8d:'d26a23',0x1e93:'f26a33',0x1e96:'4baa',0x1e98:'c79ae0'}
for pc,raw in expected.items():assert records[pc][0]==raw
for addr,value in [(0xd214,0x5ffee278),(0xd21c,0x5ffee27c)]:assert struct.unpack_from('<I',b,0x1b560+addr-0xc000)[0]==value
stores={0x1e29:[],0x1e2c:[],0x1e44:[],0x1e47:[],0x1e8d:[],0x1e93:[]}
ptr=0x5ffee278;end=ptr+64
for _ in range(8):
 ptr+=8;stores[0x1e29].append(ptr+0x104);stores[0x1e2c].append(ptr+0x108)
assert ptr==end
for ptr in range(0x5ffee27c,end,4):
 for pc,off in [(0x1e44,140),(0x1e47,204),(0x1e8d,140),(0x1e93,204)]:stores[pc].append(ptr+off)
assert all(len(stores[x])==15 for x in [0x1e44,0x1e47,0x1e8d,0x1e93])
written={a+j for addresses in stores.values() for a in addresses for j in range(4)}
assert not written.intersection(range(0x5ffedfc4,0x5ffee004))
assert 0x5ffee452 not in written
assert not written.intersection(range(0x5ffee424,0x5ffee428))
scan=json.loads((E/'rlc-store-coverage-audit.json').read_text())
assert {int(x['pc'],16) for x in scan['unknown_non_stack_base_stores'] if x['listing'].endswith('/01d10.txt')}==set(stores)
r={'firmware_sha256':hashlib.sha256(b).hexdigest(),'listing_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':len(records),'stores':[{'pc':hex(pc),'possible_dword_starts':[hex(a) for a in addresses]} for pc,addresses in stores.items()],'findings':['First loop writes16 derived DWORDs[e384,e3c4); pointer increments before paired stores.','Second loop writes15 DWORDs[e308,e344) and15[e348,e384); comparisons choose values only.','Third loop reloads saved initial pointer from stack and conditionally rewrites the same second-loop destinations. All15 iterations included irrespective of value comparisons.','These six stores cannot directly reach savedCC, gatee452 or ring indexe424 on the decoded local path. Imported coefficients affect values, not these destination bounds.'],'scope':'Local normal-entry paths, inferred DRAM map, ordinary register-window/stack behavior. Not proof about other entries, callees, other engines or later consumers.'}
(E/'rlc-derived-store-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'byte_checked_records':len(records),'store_sites':len(stores),'distinct_written_bytes':len(written)}))
