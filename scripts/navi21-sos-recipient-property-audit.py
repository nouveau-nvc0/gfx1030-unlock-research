#!/usr/bin/env python3
"""Identify ordinary recipient registration's dependency on existing SYS routing."""
import hashlib,json,lzma,pathlib
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
c=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
def rows(a,z):
 r=[{'file_offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(x['bytes'])) for x in r)==z-a
 return r
windows={hex(a):rows(a,z) for a,z in [(0x33608,0x33624),(0x3373c,0x33746),(0x33954,0x33998),(0x33c74,0x33c9e),(0x31830,0x31850),(0x30b78,0x30bd2)]}
assert b[0x31854:0x31864]==b'amd.dr.driverID\0'
d={int(x['file_offset'],0):x for rs in windows.values() for x in rs}
for a,op in [(0x3360e,'0x31830'),(0x33740,'#0x64'),(0x33992,'#0x71'),(0x33c94,'#0x74'),(0x30b8e,'r0, #0x1009'),(0x30bba,'#0xf2')]:assert d[a]['operands']==op
r={'firmware_sha256':sha,'windows':windows,'property_name':'amd.dr.driverID','property_name_file':'0x31854',
 'dataflow':[
 'Normal DR branch calls31830(headerptr), preserves returned selector inr5; selectors2/3/4 affect local component-kind selection.',
 '31830 calls30b78(headerptr,propertyname,output). On success loads result from shared output field+7448.',
 '30b78 constructs internal selector1009, packetfield4=2 and callsSVCf2(1,packet). Alternate packing chosen by319dc still reaches the samef2call.',
 'SVC64 at33740 supplies recipientID inbyte[sp+68]. SVC71 at33992 receives thatID and a descriptor whosefirstword comesfromheader+10.',
 'Later33c94 registers(selectorr5,recipientIDbyte[sp+68]) throughSVC74, subject to preceding setup success. Full enclosing CFG is not claimed.'
 ],
 'dependency_result':'This property-query route already requires recipient1 forSVCf2. It cannot independently establish the initial registration of recipient1. Trace initial table/recipient setup separately; do not infer initial SYS identity from ordinary component registration.',
 'limits':['Input image identity, full loading CFG and descriptor-to-entry installation unproved','Special loading branches may differ from ordinary property-query route','Initial8428[1] writer and runtime SYS entry remain open','No changedCCpayload or hardware acceptance'],
 'scope':'Offline source bytes and local dataflow only.'}
(E/'sos-recipient-property-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':len(d),'property':'amd.dr.driverID','query_selector':'0x1009','query_recipient':1}))
