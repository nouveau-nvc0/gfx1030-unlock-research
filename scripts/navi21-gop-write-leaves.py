#!/usr/bin/env python3
"""Inventory direct references to the x64 GOP PCI Mem.Write wrapper."""
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,'/workspace/gfx1030-unlock-research/inputs/research/bios-reference/tools/python')
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_OP_REG
root=Path('evidence/navi21-unlock/disassembly-v1')
inv=json.loads((root/'gop-inventory.json').read_text());reports=[]
for variant,leaf in [('baseline',0x62e8),('candidate',0x4e54)]:
 im=next(x for x in inv['images'] if x['variant']==variant and x['machine']=='0x8664')
 raw=Path(im['extracted']).read_bytes();assert hashlib.sha256(raw).hexdigest()==im['sha256']
 p=pefile.PE(data=raw);cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;cs.skipdata=True
 refs=[];indirect=[];skipped=[];total=0;decoded=0
 for section in p.sections:
  if not section.Characteristics&0x20000000:continue
  data=section.get_data();total+=len(data)
  for i in cs.disasm(data,section.VirtualAddress):
   decoded+=i.size
   if not i.id:skipped.append(dict(rva=hex(i.address),bytes=i.bytes.hex()));continue
   if i.mnemonic in ('call','jmp') and i.operands[0].type!=X86_OP_IMM:
    op=i.operands[0]
    indirect.append(dict(pc=hex(i.address),instruction=i.mnemonic+' '+i.op_str,
        kind='memory' if op.type==X86_OP_MEM else 'register',
        displacement=op.mem.disp if op.type==X86_OP_MEM else None))
   if i.mnemonic in ('call','jmp') and i.operands[0].type==X86_OP_IMM and i.operands[0].imm==leaf:
    owners=[f for f in p.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress<=i.address<f.struct.EndAddress]
    assert len(owners)==1
    refs.append(dict(pc=hex(i.address),owner=hex(owners[0].struct.BeginAddress)))
 assert decoded==total
 reports.append(dict(variant=variant,image_sha256=im['sha256'],leaf=hex(leaf),refs=refs,indirect_transfers=indirect,skipped=skipped,decoded_bytes=decoded,executable_bytes=total))
source=Path('evidence/navi21-unlock/cc-access-v1/amdgpu_device.c')
srcmeta=next(x for x in json.loads((source.parent/'sources.json').read_text()) if x['file']==source.name)
assert hashlib.sha256(source.read_bytes()).hexdigest()==srcmeta['sha256']
report=dict(scope='Complete executable-section linear scan with explicit skip bytes; direct leaf references only, not indirect-call closure.',images=reports,
 vram_source=srcmeta,register_constants_source=dict(file='evidence/navi21-unlock/sources/amdgpu_discovery.c',sha256=hashlib.sha256(Path('evidence/navi21-unlock/sources/amdgpu_discovery.c').read_bytes()).hexdigest()))
(root/'gop-write-leaf-inventory.json').write_text(json.dumps(report,indent=2)+'\n')
for x in reports:print(x['variant'],len(x['refs']),'sites',sorted({a['owner'] for a in x['refs']}), 'skipped',x['skipped'])
