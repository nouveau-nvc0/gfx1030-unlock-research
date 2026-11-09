#!/usr/bin/env python3
"""Offline provenance of the alternative restore flag db25."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];rows={};inputs=[]
for root in ['06f70','070d4']:
 p=E/'rlc-iram-functions'/f'{root}.txt';count=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(\S+)\s*(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;rows[pc]=(len(raw),m[3],m[4]);count+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':count})
assert rows[0x70a2][1]=='call8' and 'target=0x6944' in rows[0x70a2][2]
assert rows[0x70cc][1:] == ('s8i','a2, a13, 1')
assert rows[0x6f8a][1:] == ('movi.n','a2, 1')
# Exact contiguous path from the save call's return to flag store.
pc=0x70a5;path=[]
while pc<0x70cf:
 n,op,arg=rows[pc];assert not op.startswith(('b','ret')) and op not in ('j','jx')
 if op=='call8':assert pc==0x70c6 and 'target=0x4774' in arg
 path.append(hex(pc));pc+=n
assert pc==0x70cf
hits={hex(t):{'immediate_calls':[],'unconditional_jumps':[],'absolute_pointer_file_offsets':[]} for t in [0x6f70,0x70d4]}
for pc in range(len(code)-2):
 v=int.from_bytes(code[pc:pc+3],'little');off=v>>6
 if off&(1<<17):off-=1<<18
 if v&15==5:
  target=((pc+4)&~3)+4*off
  if hex(target) in hits:hits[hex(target)]['immediate_calls'].append(hex(pc))
 if v&63==6:
  target=pc+4+off
  if hex(target) in hits:hits[hex(target)]['unconditional_jumps'].append(hex(pc))
for t in [0x6f70,0x70d4]:
 pattern=struct.pack('<I',0x5fff0000+t)
 hits[hex(t)]['absolute_pointer_file_offsets']=[hex(i) for i in range(len(b)-3) if b[i:i+4]==pattern]
scanpath=E/'rlc-iram-store-scan-current.json';scan=json.loads(scanpath.read_text());writers=[]
for report in scan['reports']:
 for s in report['stores']:
  if s.get('address')=='0x5ffedb25':writers.append({'listing':report['listing'],**s})
assert {(x['pc'],x['source_constant']) for x in writers}=={('0x70cc',1),('0x71a4',0)}
r={'firmware_sha256':sha,'inputs':inputs,'scan_sha256':hashlib.sha256(scanpath.read_bytes()).hexdigest(),'fixed_byte_writers':writers,'return_to_flag_store_path':path,'raw_reference_scan':hits,
 'findings':[
 '6f70 setsa2=1 at6f8a; ordinary CALL8 preserves this callee register. On its local success path70a2 calls6944(0,0), then70c6 calls4774, then70cc setsbyte5ffedb25=1. No conditional branch or save-result test between70a2 return and70cc.',
 '70d4 testsdb25, calls6944(1,0) if nonzero, then after further operations clearsdb25 at71a4. This is a concrete paired local save/restore cycle with a different flag frome452.',
 'Flag1 does not independently prove the CC snapshot was successfully saved:6944/71ac internal paths and hardware waits remain conditions, and this wrapper does not inspect a returned status.',
 'Initial saved-mask zeros cannot be assumed at this alternative restore simply because the firmware file contains zeros; its known flag producer first calls the save operation.',
 'No changed saved-CC producer is established. Raw entry-reference results are below; absent ordinary references are not proof against computed/conditional/other-engine entry.'
 ],
 'limits':'Only fixed byte writers in current local scanner and exact local order. Wider writes, external transfers, other entries and actual runtime acceptance remain open. No hardware access.'}
(E/'rlc-alternative-cycle-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'flag_writers':len(writers),'path_instructions':len(path),'entry_references':hits}))
