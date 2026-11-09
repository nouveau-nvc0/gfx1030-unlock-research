#!/usr/bin/env python3
"""Raw range-wide reference check for the LX6 MQD snapshot body."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest()
assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];lo,hi=0x74c4,0x766f;hits=[]
for pc in range(len(code)-2):
 v=int.from_bytes(code[pc:pc+3],'little');off=v>>6
 if off&(1<<17):off-=1<<18
 kind='CALL' if v&15==5 else 'J' if v&63==6 else None
 if not kind:continue
 target=((pc+4)&~3)+4*off if kind=='CALL' else pc+4+off
 if lo<=target<hi and not lo<=pc<hi:hits.append({'pc':hex(pc),'target':hex(target),'kind':kind,'raw':code[pc:pc+3].hex()})
assert [(x['pc'],x['target']) for x in hits]==[('0x2101','0x7537'),('0x3cda','0x7608'),('0x6360','0x75f8'),('0x6de5','0x74c4')]
inputs=[];rows={}
for root in ['02068','03cbc','06348','06944']:
 p=E/'rlc-iram-functions'/f'{root}.txt';n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;rows[pc]=(raw,m[3]);n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':n})
containing={0x2101:0x2100,0x3cda:0x3cd8,0x6360:0x635f}
for start,raw in [(0x2100,'ac86'),(0x3cd8,'a172e5'),(0x635f,'9875')]:assert rows[start][0].hex()==raw
for hit in hits:
 pc=int(hit['pc'],16)
 if pc in containing:
  start=containing[pc]
  hit.update(classification='inside an existing decoded instruction',containing_pc=hex(start),containing_instruction=rows[start][1])
 else:
  assert rows[pc][0].hex()=='e56d00'
  hit['classification']='known direct CALL8 from6944 to74c4'
pointers=[{'file_offset':hex(i),'value':hex(struct.unpack_from('<I',b,i)[0])} for i in range(len(b)-3) if 0x5fff0000+lo<=struct.unpack_from('<I',b,i)[0]<0x5fff0000+hi]
assert not pointers
r={'firmware_sha256':sha,'snapshot_body_IRAM_offsets':[hex(lo),hex(hi)],'raw_scan_positions':len(code)-2,'external_range_hits':hits,'full_container_absolute_pointers':pointers,'inputs':inputs,
'finding':'Range-wide immediate CALL/J check retains only known6de5->74c4 on reviewed instruction streams. Three other byte matches start inside existing instructions. No initial full absolute pointer to any byte in the body.',
'limits':['Computed and conditional transitions, alternate instruction streams, other engines and relative addresses remain open.','Known direct6944 callers retain earlier default-slot31 finding; this scan adds no custom-slot producer.','Does not establish hardware execution, changed CC masks or acceptance of writes. No hardware access.']}
(E/'rlc-snapshot-entry-range-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'raw_range_hits':len(hits),'known_direct_calls':1,'inside_other_instructions':3,'absolute_pointers':len(pointers),'byte_checked_records':sum(x['byte_checked_records'] for x in inputs)}))
