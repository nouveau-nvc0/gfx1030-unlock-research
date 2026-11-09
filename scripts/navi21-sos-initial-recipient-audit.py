#!/usr/bin/env python3
"""Record the special fixed-selector loader path and its concrete caller."""
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
windows={hex(a):rows(a,z) for a,z in [(0x33440,0x3344e),(0x334b4,0x334c8),(0x335a4,0x335d6),(0x33b5a,0x33b62),(0x33c74,0x33c9e),(0x33d94,0x33dc0)]}
d={int(x['file_offset'],0):x for rs in windows.values() for x in rs}
assert 13*4+0x13c==0x170
assert d[0x335ae]['operands']=='r5, #1'
assert d[0x33d98]['operands']=='r5, #1'
assert d[0x33db2]['operands']=='r5, r4, [sp]'
assert d[0x33db8]['operands']=='0x33440'
r={'firmware_sha256':sha,'windows':windows,
 'concrete_caller':'33d98 setsr5=1,33d9e setsr4=0,33db2 stores1/0 tocallerstack,33db8 calls33440. With52-bytepush+13c locals,callee[sp+170] isfirststackarg=1.',
 'special_path':[
 'Nonzero stackarg at334ba selects334be: input image address loaded fromglobal2060d4, storedsp+20; jumps3356a. It skips the ordinary source path.',
 'At335a4 the same nonzero argument selects335a8; setsr5=1,r6=2,r10=2,r11=2 and branches3369e. It skips31830/property query.',
 'If imagekind5244 follows normalDR checks and setup succeeds,33b5a compares with4154 and selects33c5c; the alternate33b9a assignment tor5 is skipped.',
 '33c94 then submitsSVC74 withselector1 and allocatedrecipientIDbyte[sp+68]. This is a concrete possible initial registration path, conditional on untraced intermediate setup and imagekind.'
 ],
 'correction':'The previous circularity applies only to the ordinary property-query branch. A concrete caller requests the separate fixed-selector1 branch. Do not generalize ordinary registration constraints to initialization.',
 'open':['Producer/content ofimage-address global2060d4','Intermediate setup success and precise loaded image identity','SVC71 record entry installation and link toSYS dispatcher','Actual runtime registration and changedCCpayload'],
 'scope':'Offline local instruction/dataflow evidence, not complete path execution proof. No hardware changes.'}
(E/'sos-initial-recipient-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':len(d),'callee_stack_argument_offset':'0x170','concrete_requested_selector':1,'caller':'0x33db8'}))
