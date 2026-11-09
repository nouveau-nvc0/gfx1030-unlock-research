#!/usr/bin/env python3
"""Check local SYS call contexts around RLC base programming and start."""
import hashlib,json,lzma,pathlib,re,struct
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
c=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
def decode(a,z):
 r=[{'file_offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(x['bytes'])) for x in r)==z-a
 return r
windows={hex(a):decode(a,z) for a,z in [(0x25c4,0x260c),(0x2756,0x27b8),(0xf0dc,0xf166),(0x17210,0x17242),(0xe9c2,0xe9cc),(0xcb8c,0xcbb6)]}
d={int(i['file_offset'],0):i for rows in windows.values() for i in rows}
for a,target in [(0x25f8,'0x1d158'),(0x27a4,'0x1d158'),(0xf118,'0x1d158'),(0x1723c,'0xf0dc'),(0xe9c6,'0xf0dc'),(0xcba2,'0x14cf8')]:assert d[a]['mnemonic']=='bl' and d[a]['operands']==target
assert d[0xf122]['operands']=='r6, #0x3b000'
assert d[0xf13a]['operands']=='r1, r0, #1'
assert d[0xf15a]['operands']=='#0x7c'
h=(S/'gc_10_3_0_offset.h').read_text();mask=(S/'gc_10_3_0_sh_mask.h').read_text()
assert re.search(r'#define mmRLC_CNTL\s+0x4c00',h)
assert re.search(r'#define RLC_CNTL__RLC_ENABLE_F32_MASK\s+0x00000001L',mask)
assert (0xa000+0x4c00)*4==0x3b000
assert struct.unpack_from('<I',b,0x17244)[0]==0xe5c978
result={'firmware_sha256':sha,'capstone_version':capstone.__version__,'address_convention':'code positions are file offsets','windows':windows,
 'register_sources':{str(S/n):hashlib.sha256((S/n).read_bytes()).hexdigest() for n in ['gc_10_3_0_offset.h','gc_10_3_0_sh_mask.h']},
 'local_paths':[
 '25f8 and27a4 are real local BL instructions preceded by88b4; nearby1a968 return is tested before proceeding. Enclosing function entries and earlier branches remain open.',
 'f0dc loads selector from argument+4. Selectorffff permitsf118->1d158. Other selector skips base setup and uses3ed50 withbit80.',
 'On base-setup result0, SVC7b reads3b000 into stack; nonzero operation result exits. If returnedbit0 already set, local error path exits. Otherwise OR1 is passed to SVC7c at3b000.',
 'Public GC10.3 header identifies3b000 asRLC_CNTL andbit0 asRLC_ENABLE_F32.',
 '17210 calls169b4, optionally14070(18,originalarg) ifglobal[e5c978+13]!=0, then builds stackwordsffffffff/ffff/0 and callsf0dc withsecondarg1. Optional14070 nonzero result returns before call.',
 'e9c6 is another BLf0dc withr0=r7,r1=0; origin ofr7 and enclosing dispatch selection remain untraced.',
 'cba2 calls14cf8 withpointersp+8; enclosing input initialization and case selection remain untraced.'
 ],
 'scope':'Exact local Thumb call/branch context plus public register identity. SVC behavior remains a strong read/write interpretation, not resolved implementation. No complete driver-command-to-entry proof, changed payload producer, or CC acceptance.'}
(E/'psp-rlc-start-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'windows':len(windows),'decoded_instructions':len(d),'register':'RLC_CNTL','enable_mask':1}))
