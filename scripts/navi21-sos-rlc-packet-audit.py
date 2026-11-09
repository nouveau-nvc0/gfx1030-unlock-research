#!/usr/bin/env python3
"""Trace SOS construction of the two RLC-related internal SYS packets."""
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
wins={hex(a):rows(a,z) for a,z in [(0x31578,0x3159c),(0x308f2,0x3091c),(0x34564,0x345a2),(0x345ec,0x34602),(0x32204,0x32212)]}
d={int(x['file_offset'],0):x for rs in wins.values() for x in rs}
for a,op in [(0x3158a,'r0, #0x1070'),(0x3090a,'r0, #0x1059'),(0x31596,'#0xf2'),(0x30916,'#0xf2'),(0x345fc,'0x31578')]:assert d[a]['operands']==op
assert b[0x345a2+5]==0x25 and 0x345a2+2*b[0x345a2+5]==0x345ec
assert struct.unpack_from('<I',b,0x346e0)[0]==0x2060ec
r={'firmware_sha256':sha,'capstone_version':capstone.__version__,'windows':wins,
 'packet_builders':[
 {'entry':'0x31578','selector':'0x1070','fields':{'0':'0x1070','4':'2','0x38':'incoming r0'},'submission':'SVCf2(r0=1,r1=stackpacket)'},
 {'entry':'0x308f2','selector':'0x1059','fields':{'0':'0x1059','4':'2','0x38':'incoming r0','0x3c':'incoming r1','0x40':'incoming r2'},'submission':'SVCf2(r0=1,r1=stackpacket)'}],
 'upstream_candidate':'34564 reads pointerB from literal global2060ec. It selectsbits16..23 ofDWORD[B+71c]. Selector5 dispatches345ec: SVCa3, call308b2 saved intor4, then ifDWORD[B+704]==8 it calls31578(DWORD[B+700]). No explicit test of308b2 result gates this call; condition is thefield8 comparison.',
 'other_builder_caller':'3220c calls308f2(byte[r5+20],r4,0). Enclosing context remains open.',
 'limits':['SVCf2 routing into the matched SYS dispatcher is not yet traced; packet layout/selector matching is structural evidence','Meaning/producer of pointer at2060ec and command fields unestablished','Selector5 andfield8 not identified with Linux ring-command or firmware-type constants','Immediate call inventory is not an exhaustive indirect-call analysis','No changed savedCC payload or hardware acceptance'],
 'scope':'Offline local instructions and exact TBB entry. No hardware changes.'}
(E/'sos-rlc-packet-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'decoded_instructions':len(d),'packet_selectors':['0x1059','0x1070'],'outer_field_selector':5,'additional_field_value':8}))
