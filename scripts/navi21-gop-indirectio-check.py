#!/usr/bin/env python3
"""Bounded offline replay of GOP indirect-I/O dispatcher, synthetic RAM only."""
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0, '/workspace/gfx1030-unlock-research/inputs/research/bios-reference/tools/python')
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RSP, UC_X86_REG_RAX

root = Path('evidence/navi21-unlock/disassembly-v1')
inventory = json.loads((root/'gop-inventory.json').read_text())
im = next(x for x in inventory['images'] if x['variant']=='baseline' and x['machine']=='0x8664')
data = Path(im['extracted']).read_bytes()
assert hashlib.sha256(data).hexdigest()==im['sha256']
pe = pefile.PE(data=data)
refs = json.loads(Path('evidence/navi21-unlock/xt-rom-comparison-v1/full-reference-comparison.json').read_text())
payloads = {}
for variant in ('baseline', 'candidate'):
    ref = refs[variant]
    rom = Path(ref['path']).read_bytes()
    assert hashlib.sha256(rom).hexdigest()==ref['sha256']
    table = next(x for x in ref['tables']['data'] if x['index']==23)
    payloads[variant] = rom[table['offset']+4:table['offset']+table['bytes']]
    assert payloads[variant]==b'\0'*4

def run(payload, selection, stop_at_writer=False):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, 0x100000)
    uc.mem_write(0, pe.get_memory_mapped_image())
    context, bytecode, stack, end = 0x20000, 0x21000, 0x40008, 0x50000
    uc.mem_write(context+0x32, struct.pack('<Q',bytecode))
    uc.mem_write(context+0x28, struct.pack('<I',selection))
    uc.mem_write(bytecode,payload)
    uc.mem_write(stack,struct.pack('<Q',end))
    uc.reg_write(UC_X86_REG_RCX,context);uc.reg_write(UC_X86_REG_RSP,stack)
    visits=[]
    def hook(machine, address, size, user):
        visits.append(address)
        if address==0x7f18: machine.emu_stop()
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(0x8f08,end,count=1000)
    assert len(visits)<1000
    reached=0x7f18 in visits
    assert reached==stop_at_writer
    if not reached:
        assert uc.reg_read(UC_X86_REG_RAX)==0
        assert uc.reg_read(UC_X86_REG_RSP)==stack+8
    return dict(selection=selection,steps=len(visits),writer_reached=reached,
                return_value=uc.reg_read(UC_X86_REG_RAX) if not reached else None)

cases=[]
for variant,payload in payloads.items():
    for selection in (0,1,0x80,0xff):
        cases.append(dict(rom_payload=variant,**run(payload,selection)))
# Positive control only for the dispatcher: synthetic START128,WRITE226f,END.
# Stops before entering the writer; this is not a firmware modification/load test.
control=run(bytes.fromhex('0180036f2209000000'),0x80,True)
result=dict(scope='XL x64 original dispatcher instructions in Unicorn, synthetic RAM, no hardware I/O; both stock table payloads tested.',
            image_sha256=im['sha256'],stock_cases=cases,synthetic_control=control,passed=True)
(root/'gop-indirectio-replay.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS:8 stock empty-table cases; synthetic dispatcher control reaches writer hook')

