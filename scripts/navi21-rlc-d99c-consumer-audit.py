#!/usr/bin/env python3
"""Offline distinction between d99c callback scheduling and e452 restore gate."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest()
assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];dram=b[0x1b560:0x1f560];rows={};inputs=[]
for root in ['03314','0387c','038ec','03a00','03cbc','05a6c']:
 p=E/'rlc-iram-functions'/f'{root}.txt';n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(\S+)\s*(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw
   rows[pc]={'bytes':raw.hex(),'op':m[3],'operands':m[4]};n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':n})
for pc,target in [(0x38d7,0x5a6c),(0x39f9,0x5a6c),(0x3a47,0x5a6c),(0x3cf1,0x5a6c),(0x3b32,0x6944)]:assert rows[pc]['op']=='call8' and f'target={hex(target)}' in rows[pc]['operands']
assert rows[0x5a7c]['operands']=='a3, a4, 4'
assert rows[0x5a83]['operands'].startswith('a13, a2, a13')
assert rows[0x3ce8]['operands']=='a13, a3, 4'
assert rows[0x38d5]['operands']=='a10, a10, 12'
assert rows[0x3320]['operands']=='a2, a4, 8' and rows[0x3323]['operands']=='a3, a4, 12'
for p,v in [(0x5ffed27c,0x5ffed99c),(0x5ffed308,0x5fff3cbc),(0x5ffed310,0x5fff3a00),(0x5ffed484,0x5ffee57c)]:assert struct.unpack_from('<I',dram,p-0x5ffec000)[0]==v
r={'firmware_sha256':sha,'inputs':inputs,'selected_instruction_rows':{hex(pc):rows[pc] for pc in [0x3320,0x3323,0x38d5,0x38d7,0x39df,0x39e2,0x39ec,0x39f9,0x3a3c,0x3a3f,0x3a42,0x3a47,0x3a7c,0x3a81,0x3b32,0x3ce1,0x3ce8,0x3cf1,0x5a7c,0x5a83,0x5a86]},
 'findings':[
 '3cbc testsbyte[d99c]; if nonzero, passesDWORD[d9a0] andcallback5fff3a00 to5a6c at3cf1.38ec similarly schedules3a00 at39f9 when enabled.3a00 can reschedule itself at3a47 using the same enable/parameter.',
 '5a6c stores callback at5ffee580, writesmax(arg0,8) to6803b6e0, sets its active byte5ffee59e and ORsbit1 into6803b6ec. Parameter units and actual delivery are not inferred here.',
 '387c usesDWORD[d9a8], notd9a0, when scheduling3cbc at38d7.3314 sets separatebyte[d9a4] andDWORD[d9a8], applying default10000 whenarg1=0. Sharing a base pointer does not make these the same control.',
 '3a00 still loads independent gatee452 at3a7c and branches around restore whenzero at3a81. Enablingd99c can sustain callback scheduling but does not establish a nonzeroe452 producer.',
 'No call to2edc is established by these consumer paths. Concrete scheduled3a00 restore remains gated, and its later save can replace initial saved masks as previously documented.'
 ],
 'limits':'Local code and initial literal placement; callee completion, callback timing, event delivery, table mutation and hardware acceptance not observed. No hardware access.'}
(E/'rlc-d99c-consumer-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'byte_checked_records':sum(x['byte_checked_records'] for x in inputs),'callback_slot':'0x5ffee580','restore_gate_still_separate':'0x5ffee452'}))
