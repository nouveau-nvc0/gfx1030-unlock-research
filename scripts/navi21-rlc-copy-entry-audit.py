#!/usr/bin/env python3
"""Raw range-wide reference check for the LX6 shared copy body."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest()
assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];lo,hi=0xa1bd,0xa2fc;hits=[]
for pc in range(len(code)-2):
 v=int.from_bytes(code[pc:pc+3],'little');off=v>>6
 if off&(1<<17):off-=1<<18
 kind='CALL' if v&15==5 else 'J' if v&63==6 else None
 if not kind:continue
 target=((pc+4)&~3)+4*off if kind=='CALL' else pc+4+off
 if lo<=target<hi and not lo<=pc<hi:hits.append({'pc':hex(pc),'target':hex(target),'kind':kind,'raw':code[pc:pc+3].hex()})
assert [(x['pc'],x['target']) for x in hits]==[('0x135d','0xa1fc'),('0x2ce1','0xa1fc'),('0x4397','0xa218'),('0x6f88','0xa2ef')]
inputs=[];rows={}
for root in ['01348','02cd4','04374','06f70']:
 p=E/'rlc-iram-functions'/f'{root}.txt';n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;rows[pc]=(raw,m[3]);n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':n})
assert rows[0x4396][0].hex()=='d815' and rows[0x6f87][0].hex()=='b1c6d8'
for hit in hits:
 pc=int(hit['pc'],16)
 if pc in (0x4397,0x6f88):
  start=0x4396 if pc==0x4397 else 0x6f87
  hit.update(classification='inside an existing decoded instruction',containing_pc=hex(start),containing_instruction=rows[start][1])
 else:hit['classification']='known direct CALL8 to primary copy entry'
pointers=[{'file_offset':hex(i),'value':hex(struct.unpack_from('<I',b,i)[0])} for i in range(len(b)-3) if 0x5fff0000+lo<=struct.unpack_from('<I',b,i)[0]<0x5fff0000+hi]
assert not pointers
ranges=[(0x135d,0x5ffed978,20),(0x2ce1,0x5ffee438,20)]
for _,start,n in ranges:assert not(start<0x5ffee004 and start+n>0x5ffedfc4) and not start<=0x5ffee452<start+n
r={'firmware_sha256':sha,'copy_body_IRAM_offsets':[hex(lo),hex(hi)],'raw_scan_positions':len(code)-2,'external_range_hits':hits,'full_container_absolute_pointers':pointers,'inputs':inputs,'known_copy_ranges':[{'call':hex(pc),'start':hex(start),'end_exclusive':hex(start+n)} for pc,start,n in ranges],
'finding':'Scanning the entire shared-body target interval yields no additional ordinary direct entry on the known instruction streams. Two true direct copies retain prior20-byte bounds; two other encodings start inside unrelated instructions.',
'limits':['This is not a proof that overlapping instruction streams cannot ever execute; it classifies matches against existing streams.','Conditional branches, computed CALLX/JX targets, other engines and other loaded code variants are not excluded.','Absence of full absolute pointers does not exclude computed/relative targets.','No new CC/gate producer found; no hardware access.']}
(E/'rlc-copy-entry-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'raw_range_hits':len(hits),'known_direct_calls':2,'inside_other_instructions':2,'absolute_pointers':len(pointers)}))
