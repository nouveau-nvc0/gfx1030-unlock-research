#!/usr/bin/env python3
"""Check the local initialization order selecting image fielda023c."""
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
windows={hex(a):rows(a,z) for a,z in [(0x2424e,0x24308),(0x25d78,0x25d80),(0x26ad4,0x26ad6),(0x21fe8,0x2202c),(0x22030,0x2207a)]}
d={int(x['file_offset'],0):x for rs in windows.values() for x in rs}
assert d[0x242f4]['operands']=='0x24cb4'
assert d[0x242ec]['operands']=='0x25d78' and d[0x242f0]['operands']=='0x26ad4'
assert struct.unpack_from('<I',b,0x25d80)[0]==0x8898
assert struct.unpack_from('<I',b,0x243a0)[0]==0x6004
assert 0x8898+0x80==0x8918
r={'firmware_sha256':sha,'windows':windows,
 'local_order':['2424e/24252 writea0000 to[6004+30]=6034','Intervening model-selection comparisons only store byte[6004+4]','242de..24306 selectsbyte[6004+3],bothbranchesjoin242ec','25d78 zeroes128bytes[8898,8918) through21fe8;26ad4 returns immediately','242f4calls24cb4,whoseimagepointerinputis[DWORD[6034]+23c]=[a023c]'],
 'conclusion':'On this initialization branch and ordinary callee completion, the known601c producer uses fielda023c. The previously open local ordering condition is resolved; no intermediate local write changes6034.',
 'limits':['Outer choice of this boot branch remains conditional','Content/producerofa023c remainsuntraced','No actual memory/window/readback observations','This identifies an input field, not SYS image bytes or changedCCpayload'],
 'next_dependency':'Follow population of the initialization block at a0000, especiallya023c, or pin the driver-to-earlier-loader handoff. Do not identify thatfieldwithaLinuxsourcebufferwithoutthemissingtransfer.',
 'scope':'Offline exact-byte and local sequence analysis only.'}
(E/'sos-image-order-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':len(d),'input_field':'0x000a023c','intermediate_clear_interval':['0x8898','0x8918']}))
