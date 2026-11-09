#!/usr/bin/env python3
"""Record the concrete producer of kernel image pointer601c."""
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
windows={hex(a):rows(a,z) for a,z in [(0x24cb4,0x24d0c),(0x2424e,0x24254)]}
literals={hex(a):hex(struct.unpack_from('<I',b,a)[0]) for a in range(0x24d0c,0x24d28,4)}
assert list(literals.values())==['0x8438','0x6034','0xfc0fff','0xc0808000','0x32404d8','0x601c','0x60d0']
assert struct.unpack_from('<I',b,0x243a0)[0]==0x6004
r={'firmware_sha256':sha,'windows':windows,'literals':literals,
 'image_origin':'24cb4 reads P=DWORD[6034],then F=DWORD[P+23c]. Computes O=F&03ffffff;24cf0 writes04000000+O to601c.',
 'parallel_address':'Reads R=DWORD[03240000], storesR at843c, constructs64-bit(R<<26)+O and writes it at60e0/60e4. This separates local-window pointer04000000+O from the wider address.',
 'window_setup':'Record8438 gets1,R,c0808000,andDWORD[03240008]&00fc0fff;032404d8 gets c0808000. Exact physical meaning and runtime completion remain unobserved.',
 'conditional_early_pointer':'In boot branch2424e, r4=6004 andSTR[r4+30]=a0000 sets6034=a0000. If unchanged before24cb4, field source is a023c. Ordering/other writers not yet closed.',
 'locator_correction':'A raw linear candidate at24d20 is literal601c bytes decoded as STR, not an instruction in this routine. Actual producer is24cf0. Exclude24d20 from code evidence.',
 'next_dependency':'Identify the producer and meaning of input field[P+23c] and connect it with stagedSYS image bytes. Track invocation of24cb4 to validate ordering.',
 'limits':['No observation ofP/F/R oractualimagebytes','No proofloadedSYS equals offlinecontainer merely from addressformula','No changedCCpayload or acceptance'],
 'scope':'Offline exact instructions and arithmetic; no hardware changes.'}
(E/'sos-image-origin-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':sum(map(len,windows.values())),'image_pointer_store':'0x24cf0','input_field':'[DWORD[6034]+23c]','window_base':'0x04000000'}))
