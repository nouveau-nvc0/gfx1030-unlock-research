#!/usr/bin/env python3
"""Resolve indexed RLC snapshot sources against saved GC register headers."""
import hashlib,json,lzma,re
from pathlib import Path
r=Path('evidence/navi21-unlock/disassembly-v1');src=Path('evidence/navi21-unlock/sources')
files={n:src/n for n in ('gc_10_3_0_offset.h','gc_10_3_0_sh_mask.h','sienna_cichlid_ip_offset.h')}
def defs(p):
 return {m[1]:int(m[2],16) for m in re.finditer(r'^#define\s+(\w+)\s+(0x[0-9a-fA-F]+)',p.read_text(),re.M)}
o=defs(files['gc_10_3_0_offset.h']);m=defs(files['gc_10_3_0_sh_mask.h']);base=defs(files['sienna_cichlid_ip_offset.h'])['GC_BASE__INST0_SEG0'];assert base==0x1260
lanes=[]
for name,address,slots in [('CP_MQD_BASE_ADDR',0xc824,(0xc,0x10)),('CP_MQD_BASE_ADDR_HI',0xc828,(0x10c,0x110)),('CP_MQD_CONTROL',0xc8ac,(0x20c,0x210))]:
 assert (base+o['mm'+name])*4==address
 fields={k:v for k,v in m.items() if k.startswith(name+'__') and k.endswith('_MASK')}
 mask=0
 for val in fields.values():mask|=val
 lanes.append(dict(register=name,index=hex(address//4),aperture=hex(0x60000000+address),ram_offsets=[hex(x) for x in slots],fields={k:hex(v) for k,v in fields.items()},documented_bit_union=hex(mask),documented_gate_byte_mask=hex((mask>>16)&255),documented_saved_wgp_mask=hex(mask&m['CC_GC_SHADER_ARRAY_CONFIG__INACTIVE_WGPS_MASK'])))
b=lzma.decompress(Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
references={}
for address in (0x5fff6944,0x5fff74c4):
 pat=address.to_bytes(4,'little');hits=[];start=0
 while True:
  k=b.find(pat,start)
  if k<0:break
  hits.append(hex(k));start=k+1
 references[hex(address)]=hits
report=dict(scope='Source-header register mapping and literal-pointer locator, no runtime execution. Documented field union is not proof of reserved-bit readback behavior.',firmware_sha256=sha,source_hashes={k:hashlib.sha256(p.read_bytes()).hexdigest() for k,p in files.items()},lanes=lanes,literal_pointer_file_offsets=references,
 limits=['No arbitrary control of source values established.','Absence of full-address literal does not exclude computed calls or entry from another engine.','Known direct callers still select31, outside overlap range.'])
(r/'rlc-snapshot-sources.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
