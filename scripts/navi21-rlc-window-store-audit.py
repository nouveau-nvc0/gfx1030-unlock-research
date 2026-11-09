#!/usr/bin/env python3
"""Offline destination bounds for remaining LX6 window/table stores."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];dram=b[0x1b560:0x1f560];rows={};inputs=[]
for root in ['04004','04374','065d8']:
 p=E/'rlc-iram-functions'/f'{root}.txt';count=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw
   rows[pc]=(m[2],m[3]);count+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':count})
for a,raw in {0x4099:'909210',0x409c:'aa99',0x40a0:'826980',0x43a0:'80ee10',0x43a3:'a0ee80',0x43a6:'d26e80',0x43f4:'52c510',0x43f7:'c795ba',0x68df:'4b5c',0x68e1:'0c04',0x68e5:'92a028',0x68e8:'97b454',0x68fa:'d2652a',0x68fd:'1b44',0x68ff:'4b55'}.items():assert rows[a][0]==raw
for p,v in {0x5ffed28c:0xfffff,0x5ffed284:0x5ffffe00,0x5ffed33c:0x67fffe00,0x5ffed37c:0x5ffec1c8,0x5ffed380:0x5ffec120,0x5ffed4dc:0x5ffedb24}.items():assert struct.unpack_from('<I',dram,p-0x5ffec000)[0]==v
# One initial entry, followed by ten pairs ending at c1c8.
cells=[0x120];p=0x128
while True:
 cells.extend([p,p+8]);p+=16
 if p==0x1c8:break
 assert p<0x1c8
assert cells==list(range(0x120,0x1c8,8))
cc={0x60008924,0x600089bc,0x600098f4};table=[]
for off in cells:
 address,value=struct.unpack_from('<II',dram,off);dest=0x60000000+(address&0xfffff)
 assert dest not in cc
 table.append({'cell':hex(0x5ffec000+off),'initial_address_word':hex(address),'initial_value':hex(value),'destination':hex(dest)})
start=0x5ffedb24+4+168;end=start+40*4
assert (start,end)==(0x5ffedbd0,0x5ffedc70)
assert end<0x5ffedfc4
r={'firmware_sha256':sha,'inputs':inputs,'4374_initial_table':table,'65d8_loop_range':{'start':hex(start),'end_exclusive':hex(end),'maximum_words':40},
'findings':[
 '40a0 destination=(a2&fffff)+67fffe00+200, so effective base is68000000 and maximum starting offsetfffff. This cannot directly address LX6 RAM5ffe.... It does not by itself exclude hardware CC writes within the window.',
 '43a6/43c7/43e8 destination=(table_address&fffff)+5ffffe00+200, so effective base60000000. Exact21 initial table entries do not include CC_SA8924/CC_WGP89bc/CC_RB98f4. Changed table contents and register side effects are not excluded.',
 '68fa destination startsdbd0 and advances4 for counter0..39, checked before every store. Return can occur earlier; reaching count40 loops at6940 without another store. This write cannot reachdfc4 or gatee452.',
 'These results separate computed hardware-register writes from ordinary RAM writes; they do not prove the hardware windows cannot indirectly affect CC.'
],
'next':'Resolve possible hardware CC destinations of4004 from its actual local address selections and three known caller lengths; do not infer exclusion solely from the hardware window.',
'scope':'Pinned code/literal and initial table evidence only; inferred DRAM placement retained. No hardware access.'}
(E/'rlc-window-store-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'byte_checked_records':sum(x['byte_checked_records'] for x in inputs),'initial_table_entries':len(table),'loop_range':[hex(start),hex(end)]}))
