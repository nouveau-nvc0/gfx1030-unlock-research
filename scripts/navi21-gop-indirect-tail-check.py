#!/usr/bin/env python3
"""Audit fixed-displacement BAR writes and replay ATOM destination tail jumps."""
import hashlib,json,struct,sys
from pathlib import Path
sys.path.insert(0,'/workspace/gfx1030-unlock-research/inputs/research/bios-reference/tools/python')
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_AC_WRITE
from capstone.x86 import X86_OP_MEM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
r=Path('evidence/navi21-unlock/disassembly-v1');inv=json.loads((r/'gop-inventory.json').read_text());scans=[];cases=[]
for variant in ('baseline','candidate'):
 im=next(x for x in inv['images'] if x['variant']==variant and x['machine']=='0x8664')
 raw=Path(im['extracted']).read_bytes();assert hashlib.sha256(raw).hexdigest()==im['sha256']
 pe=pefile.PE(data=raw);mapped=pe.get_memory_mapped_image();cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;cs.skipdata=True
 overlaps=[];skipped=[];count=0
 for section in pe.sections:
  if not section.Characteristics&0x20000000:continue
  consumed=0
  for i in cs.disasm(section.get_data(),section.VirtualAddress):
   consumed+=i.size
   if not i.id:skipped.append(hex(i.address));continue
   for o in i.operands:
    if o.type==X86_OP_MEM and o.access&CS_AC_WRITE:
     count+=1
     if o.mem.disp<=0x106<o.mem.disp+o.size:
      overlaps.append(dict(pc=hex(i.address),instruction=i.mnemonic+' '+i.op_str,width=o.size))
  assert consumed==len(section.get_data())
 scans.append(dict(variant=variant,sha256=im['sha256'],explicit_memory_write_operands=count,overlaps=overlaps,skip_bytes=skipped))
 if variant!='baseline':continue
 targets=list(struct.unpack_from('<6Q',mapped,0xbb50))
 assert targets==[0x8fb8,0x9050,0x9064,0x90dc,0x9100,0x9100]
 for entry,contextreg,basereg in ((0x9415,UC_X86_REG_RBX,UC_X86_REG_RDI),(0x94e9,UC_X86_REG_RDI,UC_X86_REG_RSI),(0x9b09,UC_X86_REG_RBX,UC_X86_REG_RDI),(0x9baf,UC_X86_REG_RBX,UC_X86_REG_RSI)):
  for index,target in enumerate(targets):
   u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(0,0x100000);u.mem_write(0,mapped);u.mem_write(0x20044,bytes([index]));u.reg_write(UC_X86_REG_RCX,0x20000);u.reg_write(contextreg,0x20000);u.reg_write(basereg,0);u.reg_write(UC_X86_REG_RSP,0x40000)
   reached=[]
   def hook(machine,address,size,user):
    if address in targets:reached.append((address,machine.reg_read(UC_X86_REG_RCX)));machine.emu_stop()
   u.hook_add(UC_HOOK_CODE,hook);u.emu_start(entry,0x50000,count=50)
   assert reached==[(target,0x20000)],reached
   cases.append(dict(entry=hex(entry),index=index,target=hex(target)))
report=dict(scope='Fixed-displacement store locator includes write width; does not resolve shifted base pointers, dynamic index overlap or implicit memory writes. Tail replay covers six valid destination indices, not arbitrary bytes.',bar_field_scan=scans,atom_tail_cases=cases,passed=True)
(r/'gop-indirect-tail-audit.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS:24 ATOM tail cases; BAR-field displacement overlaps:',[len(s['overlaps']) for s in scans])
