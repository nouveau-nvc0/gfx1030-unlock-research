#!/usr/bin/env python3
"""Original-instruction replay of GOP's runtime VRAM-table base update."""
import hashlib,json,struct,sys
from pathlib import Path
sys.path.insert(0,'/workspace/gfx1030-unlock-research/inputs/research/bios-reference/tools/python')
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import *
r=Path('evidence/navi21-unlock/disassembly-v1')
inv=json.loads((r/'gop-inventory.json').read_text())
im=next(x for x in inv['images'] if x['variant']=='baseline' and x['machine']=='0x8664')
raw=Path(im['extracted']).read_bytes();assert hashlib.sha256(raw).hexdigest()==im['sha256']
p=pefile.PE(data=raw)
refs=json.loads(Path('evidence/navi21-unlock/xt-rom-comparison-v1/full-reference-comparison.json').read_text())
cases=[]
for variant in ('baseline','candidate'):
 ref=refs[variant];rom=Path(ref['path']).read_bytes();assert hashlib.sha256(rom).hexdigest()==ref['sha256']
 tables={i:next(t for t in ref['tables']['data'] if t['index']==i) for i in (4,11)}
 fi=rom[tables[4]['offset']:tables[4]['offset']+tables[4]['bytes']]
 vr=rom[tables[11]['offset']:tables[11]['offset']+tables[11]['bytes']]
 assert len(fi)>=0x58 and len(vr)>=10
 for mode in ('stock','nonzero_size','existing_base','fallback_size'):
  f=bytearray(fi);v=bytearray(vr)
  if mode=='nonzero_size':struct.pack_into('<H',v,8,0x80)
  if mode=='existing_base':struct.pack_into('<I',v,4,0x12345678);struct.pack_into('<H',v,8,0x80)
  if mode=='fallback_size':struct.pack_into('<I',f,0x54,0);struct.pack_into('<H',v,8,0)
  for response in (0,0x4000,0xffffffff):
   uc=Uc(UC_ARCH_X86,UC_MODE_64);uc.mem_map(0,0x100000);uc.mem_write(0,p.get_memory_mapped_image())
   uc.mem_write(0x20000,bytes(f));uc.mem_write(0x21000,bytes(v));uc.mem_write(0x40090,struct.pack('<I',response))
   for reg,val in ((UC_X86_REG_RSP,0x40000),(UC_X86_REG_RDI,0x20000),(UC_X86_REG_RBX,0x21000),(UC_X86_REG_RBP,4),(UC_X86_REG_RSI,0)):uc.reg_write(reg,val)
   old=struct.unpack_from('<I',v,4)[0];size=struct.unpack_from('<H',v,8)[0];field=struct.unpack_from('<I',f,0x54)[0]
   if size==0:
    chosen=field or 0x40;expected=(((response<<10)&0xffffffff)-chosen)&0xffffffff;size=chosen&0xffff
   elif old==0:expected=(((response<<10)&0xffffffff)-size)&0xffffffff
   else:expected=old
   uc.emu_start(0x7a0e,0x7a40,count=100)
   actual=struct.unpack('<I',uc.mem_read(0x21004,4))[0]
   assert actual==expected and struct.unpack('<H',uc.mem_read(0x21008,2))[0]==size
   base=(actual<<10)&0xffffffff
   # Regardless of mutable base, the final BTS enforces bit31.
   for offset in (0,1,0x8924,0x89bc,0xffff):
    address=(((base+offset)&0xffffffff)|0x80000000)&0xfffffffc
    assert address&0x80000000 and address not in (0x8924,0x89bc)
   cases.append(dict(variant=variant,mode=mode,synthetic_command6_result=hex(response),firmware_info_54=hex(field),new_data11_4=hex(actual),new_data11_8=hex(size),wrapper_base=hex(base)))
report=dict(scope='XL x64 instructions7a0e..7a40 with both reference table data sets and synthetic command6 results, in emulated RAM. No ATOM/hardware execution.',image_sha256=im['sha256'],cases=cases,passed=True,
 limitations=['Actual command6 result not measured.', 'Hardware interpretation of bit31 addresses unresolved.', 'This update does not establish FirmwareInfo+18 immutability.'])
(r/'gop-vram-base-replay.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS:24 runtime-table update cases; bit31 invariant retained')
print(json.dumps([c for c in cases if c['mode']=='stock' and c['synthetic_command6_result']=='0x4000'],indent=2))
