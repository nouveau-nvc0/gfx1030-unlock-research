#!/usr/bin/env python3
"""Offline direct-reference coverage for seven other callback setters."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest()
assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];dram=b[0x1b560:0x1f560]
slots=[(0x7999,0x5ffee57c,0x5a40),(0x79b6,0x5ffee58c,0x5af8),(0x79d5,0x5ffee580,0x5a6c),(0x79f2,0x5ffee590,0x5b20),(0x7a12,0x5ffee584,0x5a9c),(0x7a2e,0x5ffee594,0x5b4c),(0x7a49,0x5ffee588,0x5acc),(0x7a6a,0x5ffee598,0x5b78)]
targets={helper for _,_,helper in slots if helper!=0x5a6c};hits=[]
for pc in range(len(code)-2):
 v=int.from_bytes(code[pc:pc+3],'little');off=v>>6
 if off&(1<<17):off-=1<<18
 kind='CALL' if v&15==5 else 'J' if v&63==6 else None
 if kind:
  target=((pc+4)&~3)+4*off if kind=='CALL' else pc+4+off
  if target in targets:hits.append({'pc':hex(pc),'target':hex(target),'kind':kind})
pointers=[]
for target in targets:
 pattern=struct.pack('<I',0x5fff0000+target)
 pointers.extend({'file_offset':hex(i),'target':hex(target)} for i in range(len(b)-3) if b[i:i+4]==pattern)
assert not hits and not pointers
scanpath=E/'rlc-iram-store-scan-current.json';scan=json.loads(scanpath.read_text());reports={pathlib.Path(r['listing']).stem:r for r in scan['reports']}
entries=[];inputs=[]
for pc,slot,helper in slots:
 assert code[pc:pc+3].hex()=='e00a00'
 r=reports[f'{helper:05x}'];stores=[s for s in r['stores'] if s.get('address')==hex(slot)]
 assert len(stores)==1 and stores[0]['source']=='a3'
 p=pathlib.Path(r['listing']);count=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   a=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[a:a+len(raw)]==raw;count+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':count})
 entries.append({'callx_pc':hex(pc),'slot':hex(slot),'registration_helper':hex(helper),'registration_store':stores[0]['pc'],'initial_word':hex(struct.unpack_from('<I',dram,slot-0x5ffec000)[0]),'ordinary_direct_entry_established':helper==0x5a6c})
r={'firmware_sha256':sha,'scan_sha256':hashlib.sha256(scanpath.read_bytes()).hexdigest(),'inputs':inputs,'callback_slots':entries,'raw_seven_helper_CALL_J_matches':hits,'raw_seven_helper_full_pointers':pointers,
'finding':'The seven setters without calls in the local scan also have no raw immediate CALL/J targets or full absolute pointer references anywhere in the pinned container. The eighth setter5a6c retains known registrations387c/3cbc/3a00. No alternative restore entry is established by these seven slots.',
'limits':['Absence of ordinary references is not proof of permanent zero or unreachable execution.','Slot stores through computed addresses, wider copies, engines, relative targets and other firmware versions remain outside this check.','Raw scans cover exact helper entry addresses, not arbitrary interior entry.','No runtime callback delivery or accepted CC changes observed. No hardware access.']}
(E/'rlc-callback-unused-entry-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'callback_slots':len(entries),'helpers_with_no_raw_references':len(targets),'CALL_J_hits':len(hits),'pointer_hits':len(pointers)}))
