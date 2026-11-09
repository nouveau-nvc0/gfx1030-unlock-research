#!/usr/bin/env python3
"""Offline evidence for conditional PACE update delivery and command boundary."""
import hashlib,json,lzma,pathlib,re
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
images={}
for kind,fw,offset,expected in [('smu','smc',512,'0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'),('rlc','rlc',0xb360,'19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0')]:
 b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_'+fw+'.bin.xz').read_bytes());assert hashlib.sha256(b).hexdigest()==expected;images[kind]=b[offset:]
inputs=[];texts={}
for kind,roots in [('smu',('2b1b4','2b0ac','2b00c','2af90','2af68','2afec','2ba54')),('rlc',('07d24','083fc'))]:
 for root in roots:
  p=E/('all-entry-candidates' if kind=='smu' else 'rlc-iram-functions')/(root+'.txt');t=p.read_text();n=0
  for l in t.splitlines():
   m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',l)
   if m:
    pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert images[kind][pc:pc+len(raw)]==raw;n+=1
  texts[root]=t;inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':n})
edges=[('2b1b4',0x2b1df,0x2b0ac),('2b0ac',0x2b0bb,0x2b00c),('2b00c',0x2b01d,0x2af90),('2b00c',0x2b022,0x2af68),('2b0ac',0x2b0e8,0x2afec),('2afec',0x2affa,0x2af68),('2af68',0x2af84,0x2ba54)]
for root,pc,target in edges:
 assert re.search(rf'^0*{pc:x}:.*target=0x{target:x}\b',texts[root],re.M),(root,hex(pc))
h=(S/'gc_10_3_0_offset.h').read_text()
registers=[]
for name,addr in [('mmRLC_SMU_COMMAND',0x3b2a4),('mmRLC_SMU_ARGUMENT_1',0x3b2ac),('mmSMU_RLC_RESPONSE',0x3b01c)]:
 m=re.search(r'^#define\s+'+name+r'\s+(0x[0-9a-f]+)',h,re.M);assert m
 assert (0xa000+int(m[1],16))*4==addr
 assert re.search(r'^#define\s+'+name+r'_BASE_IDX\s+1\b',h,re.M)
 registers.append({'name':name,'host_byte':hex(addr),'smu_internal':hex(0x1200000+addr)})
# Unsigned range dispatch07d24 subtracts16, then rejects values>=21.
command_ranges={str(c):{'normalized':hex((c-16)&0xffffffff),'accepted_by_7d24_range':((c-16)&0xffffffff)<21} for c in (5,6,32)}
assert not command_ranges['5']['accepted_by_7d24_range'] and not command_ranges['6']['accepted_by_7d24_range']
r={'inputs':inputs,'header_sha256':hashlib.sha256(h.encode()).hexdigest(),'direct_call_edges':[{'caller_root':r,'pc':hex(p),'target':hex(t)} for r,p,t in edges],
'registers':registers,'commands':{'after_transfer_argument0':6,'later_argument1':5,'rlc_83fc_consumer_command':32},'7d24_range_check':command_ranges,
'conditions':['2b1b4:c8a9==1 and(cdf2!=0 or2b0fc_return!=0) reaches2b0ac','2b00c:fcd8==1 calls2af90 then2af68(0)','2afec:fcd8==1 calls2af68(1)','2af90 and2ba54 have additional own conditions; call does not prove transfer/command execution'],
'scope':'Conditional software edges and distinct command interfaces only. No executed path, main-RLCG translation, command32 origin, or CC acceptance proof.'}
(E/'smu-pace-delivery-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'listing_records':sum(x['byte_checked_records'] for x in inputs),'direct_edges':len(edges),'named_registers':len(registers)}))
