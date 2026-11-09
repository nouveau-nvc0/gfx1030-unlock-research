#!/usr/bin/env python3
"""Decode all nine initial state records, not only step0, for command41 data."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest();assert sha=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
def u32(a):return struct.unpack_from('<I',b,512+a)[0]
structures=[];targets=set()
for p in [0x101fc,0x1042c,0x1065c,0x1088c]:
 table=u32(p+0x22c);steps=[]
 for i in range(9):
  fields=list(b[512+p+36*i+30:512+p+36*i+36]);state,cursor,first,last,backfirst,backlast=fields
  assert state==cursor==0
  row={'step':i,'state':state,'cursor':cursor,'forward_range':[first,last],'reverse_range':[backfirst,backlast]}
  for key,start,end in [('forward',first,last),('reverse',backfirst,backlast)]:
   assert start<=end
   calls=[{'index':j,'target':hex(u32(table+4*j))} for j in range(start,end+1)]
   targets.update(int(c['target'],16) for c in calls);row[key]=calls
  steps.append(row)
 structures.append({'base':hex(p),'table':hex(table),'steps':steps})
assert targets=={0x1d7fc,0x1d7ec,0x1ef4c,0x1ef20,0x1da98,0x1da4c,0x1da28,0x1da18,0x1da5c}
inputs=[];edges=[];records={}
for root in sorted(targets):
 p=E/'all-entry-candidates'/f'{root:05x}.txt';n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[512+pc:512+pc+len(raw)]==raw;records[pc]=(m[2],m[3]);n+=1
   target=re.search(r'target=(0x[0-9a-f]+)',m[3])
   if target:edges.append({'root':hex(root),'pc':hex(pc),'target':target[1]})
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'records':n})
assert records[0x1ef44][0]=='826940'
assert u32(0x12f28)==0xff8c and u32(0x12f2c)==0x141d600 and u32(0x132c8)==0x80000
r={'firmware_sha256':sha,'structures':structures,'initial_callback_targets':[hex(x) for x in sorted(targets)],'inputs':inputs,'direct_edges':edges,'findings':['Only step0 is universally empty in the initial image. Other state records already have nonzero callback ranges; their existence does not require an unidentified runtime initializer. This refines the previous next-step choice.','Four structures contain nine36-byte state records before pair area+15c. Enumerated forward/reverse initial ranges resolve to nine distinct callbacks. This is initial-layout coverage, not proof that all state indices are bounded to nine.','Several nonempty callbacks operate on a separate structureff8c through28b50/28b80 and1ed28.1ef4c schedules callback1efa0 through295a4.1ef20 also directly ORs80000 into0141d700.','No direct global15874 assignment is present in these nine local callback bodies. Their callees, scheduling and other runtime writers remain open; no stable-pointer or no-CC conclusion follows.'],'next':'Trace concrete ff8c state consumers and scheduled1efa0 only to identify actual register destinations and any saved-CC relationship; avoid further generic searches for an initializer that the initial image already supplies.','scope':'Offline initial state/function mapping and byte-checked local callback bodies. Command delivery, state reachability, runtime mutations and hardware acceptance remain unproved.'}
(E/'smu-command41-initial-ranges-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'state_records':36,'callbacks':len(targets),'byte_checked_records':sum(x['records'] for x in inputs),'direct_edges':len(edges)}))
