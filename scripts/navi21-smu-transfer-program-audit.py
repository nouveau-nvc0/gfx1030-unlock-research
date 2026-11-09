#!/usr/bin/env python3
"""Offline reconstruction of the observed 140-byte SMU transfer program."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
S=pathlib.Path('evidence/navi21-unlock/sources')
blob=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes())
assert hashlib.sha256(blob).hexdigest()=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
b=blob[512:]
reference=(S/'pl330.c.v6.12').read_text()
for name,value in {'CMD_DMAMOV':0xbc,'CMD_DMALP':0x20,'CMD_DMALPEND':0x28,'CMD_DMALD':4,'CMD_DMAST':8,'CMD_DMAEND':0,'CMD_DMANOP':0x18,'DBGSTATUS':0xd00,'DBGCMD':0xd04,'DBGINST0':0xd08,'DBGINST1':0xd0c}.items():
 m=re.search(r'^#define\s+'+name+r'\s+(0x[0-9a-f]+)',reference,re.M);assert m and int(m[1],16)==value,name
assert re.search(r'#define\s+CC_SRCINC\s+\(1 << 0\)',reference)
assert re.search(r'#define\s+CC_DSTINC\s+\(1 << 14\)',reference)
inputs=[]
for root in ('20490','209d4','209e8','2aea8','2af90','2b0fc'):
 p=E/'all-entry-candidates'/(root+'.txt');data=p.read_bytes();count=0
 for line in data.decode().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[pc:pc+len(raw)]==raw;count+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(data).hexdigest(),'byte_checked_records':count})
desc=bytearray(b[0xfca0:0xfcb4]);assert struct.unpack_from('<II',desc,4)==(0x123ed68,140)
assert list(desc[12:18])==[1,0,1,0,0,0]
# Source assigned by20a25 ->209d4; runtime buffer values are not assumed.
struct.pack_into('<I',desc,0,0xfce8)
program=bytearray(b[0x12dc0:0x12de8]);assert program.hex()=='bc0000000000bc0200000000bc0100000000200004083802bc010000000020000408380200181818'
program[2:6]=desc[0:4];program[8:12]=desc[4:8]
# Reproduce204c7..20519 in instruction order.
ccr=0
ccr=(ccr&0xfffffffe)|(desc[12]&1)
ccr=(ccr&0xffffbfff)|((desc[13]&1)<<14)
ccr=(ccr&0xfffffff1)|4
ccr=(ccr&0xfffc7fff)|0x10000
ccr=(ccr&0xffffc7ff)|0x1000
ccr=(ccr&0xf1ffffff)|0x4000000
length=struct.unpack_from('<I',desc,8)[0]
full=length>>6;tail=(length-(full<<6))>>2
assert full==2 and tail==3
burst=ccr|0xf0|0x3c0000
struct.pack_into('<I',program,14,burst);program[19]=full-1
rest=(ccr&0xffffff0f)&0xffc3ffff
struct.pack_into('<I',program,26,rest);program[31]=tail-1
# Interpret only the unconditional instruction subset in this pinned template.
regs={};loops={};fifo=[];writes=[];trace=[];pc=0
for step in range(200):
 op=program[pc];trace.append(pc)
 if op==0:break
 if op==0xbc:
  regs[program[pc+1]]=struct.unpack_from('<I',program,pc+2)[0];pc+=6
 elif op in (0x20,0x22):
  loops[(op>>1)&1]=program[pc+1]+1;pc+=2
 elif op in (0x38,0x3c):
  idx=(op>>2)&1;loops[idx]-=1
  pc=pc-program[pc+1] if loops[idx] else pc+2
 elif op==4:
  c=regs[1];size=1<<((c>>1)&7);n=((c>>4)&15)+1
  assert size==4 and not fifo
  for _ in range(n):
   fifo.append(regs[0]);regs[0]+=size if c&1 else 0
  pc+=1
 elif op==8:
  c=regs[1];size=1<<((c>>15)&7);n=((c>>18)&15)+1
  assert size==4 and len(fifo)==n
  for _ in range(n):
   writes.append({'source':hex(fifo.pop(0)),'destination':hex(regs[2]),'bytes':size})
   regs[2]+=size if c&(1<<14) else 0
  pc+=1
 else:raise AssertionError((pc,op))
else:raise AssertionError('instruction bound')
assert not fifo and len(writes)==35
assert [int(w['source'],16) for w in writes]==list(range(0xfce8,0xfd74,4))
assert {w['destination'] for w in writes}=={'0x123ed68'}
r={'firmware_sha256':hashlib.sha256(blob).hexdigest(),'reference_sha256':hashlib.sha256(reference.encode()).hexdigest(),'inputs':inputs,'template_address':'0x12dc0','descriptor_address':'0xfca0','source_assignment':'20a22/20a25 ->209d4','program_hex':program.hex(),'ccr_burst':hex(burst),'ccr_tail':hex(rest),'executed_instruction_offsets':trace,'word_transfers':writes,'scope':'Conditional reconstruction of observed software inputs and PL330 instruction semantics, not hardware execution or identification of destination RAM behind the port.'}
(E/'smu-transfer-program-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'word_transfers':len(writes),'distinct_destinations':len({w['destination'] for w in writes}),'listing_records':sum(x['byte_checked_records'] for x in inputs),'ccr':[hex(burst),hex(rest)]}))
