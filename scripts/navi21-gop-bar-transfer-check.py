#!/usr/bin/env python3
"""Replay GOP BAR transfer helpers, stopping at synthetic PCI callbacks."""
import hashlib,json,struct,sys
from pathlib import Path
sys.path.insert(0,'/workspace/gfx1030-unlock-research/inputs/research/bios-reference/tools/python')
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
r=Path('evidence/navi21-unlock/disassembly-v1');inv=json.loads((r/'gop-inventory.json').read_text());cases=[];bodies=[];identities=[]
for variant,entry in [('baseline',0x69fc),('candidate',0x6bcc)]:
 im=next(x for x in inv['images'] if x['variant']==variant and x['machine']=='0x8664')
 raw=Path(im['extracted']).read_bytes();assert hashlib.sha256(raw).hexdigest()==im['sha256'];p=pefile.PE(data=raw);mapped=p.get_memory_mapped_image();identities.append(dict(variant=variant,sha256=im['sha256']))
 f=next(x for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==entry)
 bodies.append(mapped[entry:f.struct.EndAddress])
 for size in (0,1,2,3,4,5,8,0x9c0):
  for read in (0,1):
   for bar in (0,3):
    u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(0,0x100000);u.mem_write(0,mapped)
    u.mem_write(0x20020,struct.pack('<Q',0x21000));u.mem_write(0x20106,bytes([bar]))
    u.mem_write(0x21010,struct.pack('<QQ',0x50000,0x50010))
    stack=0x40008;u.mem_write(stack,struct.pack('<Q',0x50020));u.mem_write(stack+0x28,struct.pack('<I',size));u.mem_write(stack+0x30,bytes([read]))
    for reg,val in ((UC_X86_REG_RSP,stack),(UC_X86_REG_RCX,0x20000),(UC_X86_REG_RDX,0x22000),(UC_X86_REG_R8,0x8924)):u.reg_write(reg,val)
    seen=[]
    def hook(machine,address,length,user):
     if address in (0x50000,0x50010):
      sp=machine.reg_read(UC_X86_REG_RSP)
      seen.append(dict(callback='read' if address==0x50000 else 'write',width=machine.reg_read(UC_X86_REG_RDX),bar=machine.reg_read(UC_X86_REG_R8)&255,offset=machine.reg_read(UC_X86_REG_R9),count=struct.unpack('<Q',machine.mem_read(sp+0x28,8))[0],buffer=struct.unpack('<Q',machine.mem_read(sp+0x30,8))[0]))
      machine.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook);u.emu_start(entry,0x50020,count=100)
    width=2 if size%4==0 else 1 if size%2==0 else 0
    assert seen==[dict(callback='read' if read else 'write',width=width,bar=bar,offset=0x8924,count=size>>width,buffer=0x22000)],seen
    cases.append(dict(variant=variant,size=size,read=bool(read),**seen[0]))
report=dict(scope='Original XL and XT instructions, synthetic context/protocol callbacks, stop before callback execution. BAR3 cases are controls, not established stock invocation.',images=identities,cases=cases,identical_bodies=bodies[0]==bodies[1],passed=True)
(r/'gop-bar-transfer-replay.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS',len(cases),'cases; identical helper bodies:',report['identical_bodies'])
