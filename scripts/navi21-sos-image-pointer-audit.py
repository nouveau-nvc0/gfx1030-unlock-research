#!/usr/bin/env python3
"""Record image-source pointer initialization and independent command-window base."""
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
windows={hex(a):rows(a,z) for a,z in [(0x32f70,0x32fba),(0x2677c,0x26780),(0x26920,0x26924),(0x334b4,0x334c8)]}
assert struct.unpack_from('<I',b,0x330cc)[0]==0x206070
assert struct.unpack_from('<I',b,0x330c8)[0]==0x3010000
assert struct.unpack_from('<I',b,0x26a30)[0]==0x601c
assert 0x260d0+struct.unpack_from('<I',b,0x26158)[0]==0x2677c
assert (0x26158-0x260d0)//4+0x51==0x73
r={'firmware_sha256':sha,'windows':windows,
 'image_pointer_chain':'32fb6 SVC73 -> table26158 ->2677c literal601c ->26920 LDRresult ->32fb8 STR[r5+64],r5=206070 ->2060d4. Specialloader334be reads thatpointer.',
 'command_window_chain':'32f72 loads literal03010000,32f7e stores[r5+7c]=2060ec. This identifies earlier B numerically if initialization completes.',
 'resolved_command_addresses':{'selector_word':'0x0301071c','field_equal_8':'0x03010704','argument_word':'0x03010700'},
 'important_distinction':'Theimagepointer comes fromkernelglobal601c, while commandwindowB is a fixed constant. Neither is the previously analyzed RLC snapshot base.',
 'open':['Producer/valueofkernelglobal601c','Identity/content ofimage pointed to by601c','Public meanings of03010700/704/71c','Runtime initialization success and registration','ChangedCCpayload producer and acceptance'],
 'scope':'Offline local dataflow, preserving earlier kernel mapping assumptions. No hardware accesses.'}
(E/'sos-image-pointer-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':sum(map(len,windows.values())),'image_pointer_source':'kernelglobal0x601c','command_window':'0x03010000'}))
