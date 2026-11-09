#!/usr/bin/env python3
"""Raw immediate-entry search and byte evidence for restore caller conditions."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];targets=(0x2edc,0x70d4,0x71ac,0x6944);hits={hex(t):{'CALL':[],'J':[],'absolute_pointer_file_offsets':[]} for t in targets}
for pc in range(len(code)-2):
 v=int.from_bytes(code[pc:pc+3],'little');off=v>>6
 if off&(1<<17):off-=1<<18
 if v&15==5:
  dest=((pc+4)&~3)+4*off
  if dest in targets:hits[hex(dest)]['CALL'].append({'pc':hex(pc),'window':((v>>4)&3)*4,'raw':code[pc:pc+3].hex()})
 if v&63==6:
  dest=pc+4+off
  if dest in targets:hits[hex(dest)]['J'].append({'pc':hex(pc),'raw':code[pc:pc+3].hex()})
for t in targets:
 pat=struct.pack('<I',0x5fff0000+t)
 hits[hex(t)]['absolute_pointer_file_offsets']=[hex(i) for i in range(len(b)-3) if b[i:i+4]==pat]
assert not hits['0x2edc']['CALL'] and not hits['0x70d4']['CALL']
assert all(not hits[hex(t)]['J'] for t in targets)
assert not hits['0x2edc']['absolute_pointer_file_offsets'] and not hits['0x70d4']['absolute_pointer_file_offsets']
assert [x['pc'] for x in hits['0x71ac']['CALL']]==['0x6a95']
assert [x['pc'] for x in hits['0x6944']['CALL']]==['0x2f15','0x36ca','0x3982','0x3b32','0x3c0e','0x70a2','0x7142']
inputs=[]
for root in ['02edc','070d4','06944','071ac','035d8','03a00']:
 p=E/'rlc-iram-functions'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'records':n})
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'scan_bytes':len(code),'candidate_starts':len(code)-2,'hits':hits,'listings':inputs,
'caller_conditions':{'35d8':'e452!=0; registered77cc->32a4 route known','3a00':'e452!=0; deferred callback route known','2edc':'hardware6803ed50bit1 and byte5ffed99c nonzero; function invocation not established','70d4':'byte5ffedb25 nonzero; function invocation not established'},
'scope':'All byte positions searched for Xtensa immediate CALL/J encodings; matching known calls crosschecked against listings. Not a complete instruction decoder or CFG. Computed targets, conditional-entry edges, alternate instruction streams and other segments remain outside proof. e452 is a route-specific requirement, not a universal prerequisite for every possible CC write.'}
(E/'rlc-restore-entry-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'scan_bytes':len(code),'candidate_starts':len(code)-2,'listing_records':sum(x['records'] for x in inputs),'direct6944':len(hits['0x6944']['CALL']),'direct71ac':len(hits['0x71ac']['CALL'])}))
