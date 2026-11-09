#!/usr/bin/env python3
"""Bounded direct-reference locator for CC destinations in SYS/SOS firmware."""
import hashlib,json,lzma,pathlib,struct
import capstone
from capstone.arm import ARM_OP_IMM
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
values={0x8924,0x89bc,0x98f4,0x2249,0x226f,0x263d,0x5ffedfc4,0x5ffedfe4,0x5ffee452}
for base in (0x1200000,0x60000000,0x68000000):
 values.update(base+x for x in (0x8924,0x89bc,0x98f4))
literals={hex(v):[hex(i) for i in range(len(b)-3) if b[i:i+4]==struct.pack('<I',v)] for v in sorted(values)}
# These are possible instruction starts, not proven code boundaries.
hits=[]
for mode,step in [(capstone.CS_MODE_THUMB,2),(capstone.CS_MODE_ARM,4)]:
 c=capstone.Cs(capstone.CS_ARCH_ARM,mode);c.detail=True
 for lo,hi in [(0x1000,0x21870),(0x21970,0x35bd0)]:
  for a in range(lo,hi-3,step):
   ins=next(c.disasm(b[a:a+4],a,count=1),None)
   if ins and ins.mnemonic in ('mov','movw','mov.w','mvn','mvn.w'):
    for o in ins.operands:
     if o.type==ARM_OP_IMM:
      v=(~o.imm&0xffffffff) if ins.mnemonic.startswith('mvn') else o.imm&0xffffffff
      if v in values:hits.append({'offset':hex(a),'mode':mode,'bytes':ins.bytes.hex(),'instruction':ins.mnemonic+' '+ins.op_str,'value':hex(v)})
assert not hits and not any(literals.values())
r={'firmware_sha256':sha,'candidate_values':[hex(v) for v in sorted(values)],'all_byte_dword_matches':literals,'decoded_immediate_matches':hits,
 'scan_intervals':[['0x1000','0x21870'],['0x21970','0x35bd0']],
 'scope':'All-byte DWORD lookup over container and ARM/Thumb MOV/MOVW/MVN candidate starts in two component intervals. Not a full instruction/dataflow or code-coverage proof.',
 'does_not_exclude':['PC-relative base plus offset','MOVW/MOVT construction','computed register tables','access through a supplied argument or copied whole block','a different firmware component'],
 'next_action':'Direct constants do not supply a changed-CC producer here. Follow computed transfer destinations/contents or known saved-state writers; do not expand another generic literal inventory.',
 'hardware_changes':False}
(E/'psp-cc-reference-audit.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'values':len(values),'literal_hits':sum(map(len,literals.values())),'immediate_hits':len(hits)}))
