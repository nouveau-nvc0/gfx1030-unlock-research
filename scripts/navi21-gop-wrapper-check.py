#!/usr/bin/env python3
"""Replay original XL GOP address wrappers with reference ROMs in synthetic RAM."""
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0, '/workspace/gfx1030-unlock-research/inputs/research/bios-reference/tools/python')
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_RSP
root = Path('evidence/navi21-unlock/disassembly-v1')
refs = json.loads(Path('evidence/navi21-unlock/xt-rom-comparison-v1/full-reference-comparison.json').read_text())
inv = json.loads((root/'gop-inventory.json').read_text())
im = next(x for x in inv['images'] if x['variant']=='baseline' and x['machine']=='0x8664')
data = Path(im['extracted']).read_bytes()
assert hashlib.sha256(data).hexdigest()==im['sha256']
pe = pefile.PE(data=data)
results=[]
for variant in ('baseline','candidate'):
    ref=refs[variant];rom=Path(ref['path']).read_bytes()
    assert hashlib.sha256(rom).hexdigest()==ref['sha256']
    header=struct.unpack_from('<H',rom,0x48)[0]
    master=struct.unpack_from('<H',rom,header+0x20)[0]
    offsets={i:struct.unpack_from('<H',rom,master+4+2*i)[0] for i in (4,11)}
    for i,off in offsets.items():
        assert off==next(x['offset'] for x in ref['tables']['data'] if x['index']==i)
    scratch=struct.unpack_from('<I',rom,offsets[4]+0x18)[0]
    packed=struct.unpack_from('<I',rom,offsets[11]+4)[0]
    base=(packed<<10)&0xffffffff
    assert scratch==0x4c and packed==0
    cases=[]
    for entry in (0x2cb8,0x87dc):
        for index in (0,1,8,10,0x21fd,0x2223,0x8924,0x89bc,0xffff,0x10008):
            uc=Uc(UC_ARCH_X86,UC_MODE_64)
            uc.mem_map(0,0x400000)
            uc.mem_write(0,pe.get_memory_mapped_image())
            uc.mem_write(0x100000,rom)
            uc.mem_write(0xcdb0,struct.pack('<Q',0x20000))
            uc.mem_write(0x20070,struct.pack('<QQ',0x100000,0x21000))
            uc.reg_write(UC_X86_REG_RSP,0x40008)
            uc.reg_write(UC_X86_REG_RCX,index)
            uc.reg_write(UC_X86_REG_RDX,0x12345678)
            observed=[]
            def hook(machine,address,size,user):
                if address==0x6468:
                    observed.append((machine.reg_read(UC_X86_REG_RCX),machine.reg_read(UC_X86_REG_RDX),machine.reg_read(UC_X86_REG_R8)))
                    machine.emu_stop()
            uc.hook_add(UC_HOOK_CODE,hook)
            uc.emu_start(entry,0x50000,count=200)
            expected=((index&0xffff)+scratch) if entry==0x2cb8 else ((((index&0xffff)+base)&0xffffffff)|0x80000000)>>2
            assert observed==[(0x21000,expected,0x12345678)],(entry,index,observed)
            cases.append(dict(entry=hex(entry),input=hex(index),writer_index=hex(expected),byte_address=hex((expected<<2)&0xffffffff)))
    high_addresses={(((i+base)&0xffffffff)|0x80000000)&0xfffffffc for i in range(65536)}
    assert all(a&0x80000000 for a in high_addresses)
    assert not high_addresses.intersection((0x8924,0x89bc))
    results.append(dict(variant=variant,rom_sha256=ref['sha256'],table_offsets=offsets,scratch_base=hex(scratch),vram_packed=hex(packed),
        cases=cases,high_route_unique_addresses=len(high_addresses),high_route_min=hex(min(high_addresses)),high_route_max=hex(max(high_addresses))))
report=dict(scope='Original XL x64 wrapper instructions, both reference ROM data sets, synthetic RAM; stop before generic writer. No hardware accesses. XT code not replayed.',
    image_sha256=im['sha256'],results=results,passed=True,
    limitations=['Caller reachability and mutable ROM copies not proved.', 'High-bit address hardware interpretation and aliasing not proved.', 'No accepted CC writes demonstrated.'])
(root/'gop-wrapper-replay.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS:40 original-instruction wrapper cases; exhaustive high-route address model for both reference tables')
