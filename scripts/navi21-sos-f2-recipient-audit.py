#!/usr/bin/env python3
"""Trace dynamic recipient selection for the internal RLC packet."""
import hashlib,json,lzma,pathlib,struct
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
c=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
def rows(a,z):
 r=[{'file_offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(x['bytes'])) for x in r)==z-a
 return r
windows={hex(a):rows(a,z) for a,z in [(0x234c4,0x23690),(0x253f8,0x25416),(0x26780,0x2678c),(0x33c8e,0x33c9a),(0x350e4,0x350ea)]}
assert struct.unpack_from('<I',b,0x23694)[0]==0x8428
assert struct.unpack_from('<I',b,0x25418)[0]==0x8428
assert 0x260d0+struct.unpack_from('<I',b,0x2615c)[0]==0x26780
assert (0x2615c-0x260d0)//4+0x51==0x74
r={'firmware_sha256':sha,'capstone_version':capstone.__version__,'windows':windows,
 'recipient_route':[
 '234c4 saves packet pointer inr7; checks destination selector<16. Reads byte[8428+selector] intor5; zero returns2f.',
 'Destination selector1 takes branch23516. Recipient record pointer is [6054]+92*r5. Its byte+34 supplies a four-bit slot-use map; all slots used returns31.',
 'Further caller-state and packet/stack location conditions can return2e/32. No runtime satisfaction is established.',
 'For selected slot, updates saved frame: caller identity at+4, packet pointer at+8, mode at+c; obtains recipient entry from record+4 and stores it at savedPC+3c. This is state preparation, not a direct BL intoSYS.',
 'End calls2457c; subsequent scheduling/frame return still needs tracing to establish actual delivery.'
 ],
 'registration_route':'SVC74 tableentry2615c ->26780 ->253f8. Saved argument0 is selector; lowbyte ofargument1 is recipient ID. Helper2310c must return0 and selector<16 before STRB[8428+selector]=recipient.',
 'registration_candidates':[{'site':'0x33c94','selector':'r5','recipient':'byte[sp+68]','scope':'preceding initialization and r5 source not yet traced'},{'site':'0x350e8','selector':'r5','recipient':0,'scope':'clears selected table entry after f2 call; wider context open'}],
 'next_dependency':'Trace33c94 withr5=1 and identify the resulting recipient record/entry. This is needed to connect1070 packet to the knownSYS dispatcher.',
 'limits':['Runtime table contents and recipient identity unobserved','Kernel payload-relative mapping remains the existing inference','No changed CC payload or hardware acceptance demonstrated'],
 'scope':'Offline exact-byte analysis only.'}
(E/'sos-f2-recipient-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':sum(map(len,windows.values())),'recipient_table':'0x8428','registration_operation':'0x74','registration_candidate':'0x33c94'}))
