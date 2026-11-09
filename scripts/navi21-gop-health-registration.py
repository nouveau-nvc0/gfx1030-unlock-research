#!/usr/bin/env python3
"""Byte-checked identification of GOP DriverHealth repair notification callbacks."""
import hashlib,json,sys,uuid
from pathlib import Path
sys.path.insert(0,'/workspace/gfx1030-unlock-research/inputs/research/bios-reference/tools/python')
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
root=Path('evidence/navi21-unlock/disassembly-v1');inv=json.loads((root/'gop-inventory.json').read_text());reports=[]
cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
for variant,regstart,regend,repair,notify in [('baseline',0x926,0x95b,0x4dc0,(0x4e19,0x4e21)),('candidate',0x99a,0x9cf,0x4dd8,(0x4e31,0x4e39))]:
 im=next(x for x in inv['images'] if x['variant']==variant and x['machine']=='0x8664');raw=Path(im['extracted']).read_bytes();assert hashlib.sha256(raw).hexdigest()==im['sha256'];p=pefile.PE(data=raw);m=p.get_memory_mapped_image()
 rows=[];guid=None;materialized=[]
 for i in cs.disasm(m[regstart:regend],regstart):
  rows.append(dict(pc=hex(i.address),bytes=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str))
  if i.mnemonic=='lea' and i.operands[1].type==X86_OP_MEM and i.operands[1].mem.base==X86_REG_RIP:
   address=i.address+i.size+i.operands[1].mem.disp
   if i.reg_name(i.operands[0].reg)=='rdx':guid=str(uuid.UUID(bytes_le=m[address:address+16]))
   if i.reg_name(i.operands[0].reg)=='rax':materialized.append(address)
 assert guid=='2a534210-9280-41d8-ae79-cada01a2b127' and repair in materialized
 for pc in notify:assert m[pc:pc+2]==bytes.fromhex('ffd3')
 f=next(x for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==repair)
 body=m[repair:f.struct.EndAddress]
 reports.append(dict(variant=variant,image_sha256=im['sha256'],guid=guid,registration=rows,repair=hex(repair),repair_body_sha256=hashlib.sha256(body).hexdigest(),notify_calls=[hex(x) for x in notify]))
source=json.loads((root/'gop-DriverHealth.source.json').read_text());assert hashlib.sha256((root/'gop-DriverHealth.h').read_bytes()).hexdigest()==source['sha256']
(root/'gop-health-registration.json').write_text(json.dumps(dict(scope='Static registration/signature identification. External callback implementation not supplied or executed.',source=source,images=reports,passed=True),indent=2)+'\n')
print('PASS:both GOP registrations identify DriverHealth.Repair')
